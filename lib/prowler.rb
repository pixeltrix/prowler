# Prowler is a plugin for integrating apps with the Prowl iPhone application.
#
# === Installation
#
# From your project's RAILS_ROOT, run:
#
#   script/plugin install git://github.com/pixeltrix/prowler.git
#
# === Configuration
#
# You should have something like this in config/initializers/prowler.rb.
#
#   Prowler.configure do |config|
#     config.api_key = 'ffffffffffffffffffffffffffffffffffffffff'
#     config.application = 'www.example.com'
#   end
#
# You can test that Prowler is working in your production environment by using
# this rake task (from RAILS_ROOT):
#
#   rake prowler:test
#
# If everything is configured properly the task will send a request to
# prowl.weks.net which will be appear on your iPhone after a short delay.
#
# === Usage
#
# To use Prowler within your application just call the notify method, e.g.
#
#   Prowler.notify "Event", "Description", Prowler::Priority::NORMAL
#
# If you need to send to multiple accounts from within a single application you
# can create an instance of the Prowler class to override the global settings, e.g.
#
#   prowler = Prowler.new('apikey', 'application')
#   prowler.notify "Event", "Description", Prowler::Priority::NORMAL
#
# If performance is a concern then there is built in support for Delayed::Job.
# This can done either on a global basis, e.g.
#
#   Prowler.configure do |config|
#     config.delayed = true
#   end
#
# or on a individual message basis, e.g.
#
#   Prowler.notify "Event", "Description", Prowler::Priority::NORMAL, true
#
# === About
#
# Prowler relies upon the Prowl iPhone application which is advertised as
# a Growl notification forwarder from your Mac. However they provide an API
# which can be called by a generic script which allows you to use the
# application as a general push notification application for your iPhone.
#
# For more about the Prowl application see: http://prowl.weks.net/

require 'logger'
require 'net/https'
require 'uri'

class Prowler

  SERVICE_URL = "https://prowl.weks.net/publicapi"
  USER_AGENT = "Prowler/1.1.1"
  MULTIPLE_APIKEY_COMMANDS = %w(add)

  module Priority
    VERY_LOW  = -2
    MODERATE  = -1
    NORMAL    = 0
    HIGH      = 1
    EMERGENCY = 2
  end

  class ConfigurationError < StandardError; end

  class DelayedJob
    attr_accessor :api_key, :provider_key, :application
    attr_accessor :event, :message, :priority, :url

    def initialize #:nodoc:
      yield self if block_given?
    end

    # Send notification
    def perform
      prowler = Prowler.new(api_key, application, provider_key)
      prowler.notify(event, message, options)
    end

    def options
      { :priority => priority, :url => url, :delayed => false }
    end
  end

  class << self
    attr_accessor :api_key, :provider_key
    attr_accessor :application, :send_notifications
    attr_accessor :read_timeout, :open_timeout #:nodoc:
    attr_accessor :delayed, :verify_certificate, :root_certificates

    # Call this method to configure your account details in an initializer.
    def configure
      yield self
    end

    def send_notifications #:nodoc:
      @send_notifications.nil? ? true : !!@send_notifications
    end

    def delayed #:nodoc:
      @delayed.nil? ? false : !!@delayed
    end

    # Reset configuration
    def reset_configuration
      @application = @api_key = @provider_key = nil
      @delayed = @verify_certificate = @root_certificates = nil
      @send_notifications = @read_timeout = @open_timeout = nil
    end

    # Whether the library has been configured
    def configured?
      !@application.nil? && !@api_key.nil?
    end

    # Whether to verify the server's SSL certificate
    def verify_certificate?
      @verify_certificate.nil? ? true : !!@verify_certificate
    end

    # Location of the root certificates file.
    # Default: RAILS_ROOT/config/cacert.pem
    def root_certificates
      @root_certificates ||= File.join(RAILS_ROOT, "config", "cacert.pem")
    end

    # Returns the default logger or a logger that prints to STDOUT.
    def logger
      @logger ||= rails_logger
    end

    # Override the default logger
    def logger=(new_logger)
      @logger = new_logger
    end

    def rails_logger #:nodoc
      if defined?(Rails.logger)
        Rails.logger
      elsif defined?(RAILS_DEFAULT_LOGGER)
        RAILS_DEFAULT_LOGGER
      else
        Logger.new(STDERR)
      end
    end

    def read_timeout #:nodoc:
      @read_timeout ||= 5
    end

    def open_timeout #:nodoc:
      @open_timeout ||= 2
    end

    # Send a notification to your iPhone:
    # * event:    The title of notification you want to send.
    # * message:  The text of the notification message you want to send.
    #
    # The following options are supported:
    # * +:delayed+:  Whether to use Delayed::Job to send notifications. (Optional)
    # * +:priority+: The priority of the notification - see Prowler::Priority. (Optional)
    # * +:url+:      A custom url for the Prowl application to open. (Optional)
    def notify(event, message, *args)
      raise ConfigurationError, "You must provide an API key to send notifications" if api_key.nil?
      raise ConfigurationError, "You must provide an application name to send notifications" if application.nil?

      if args.first.is_a?(Hash)
        options = args.first
        options[:priority] ||= Priority::NORMAL
        options[:delayed] ||= delayed
      else
        options = {
          :priority => args.shift || Priority::NORMAL,
          :delayed => args.shift || delayed
        }
      end

      if options.delete(:delayed)
        enqueue_delayed_job(self, event, message, options)
      else
        perform(
          :add, api_key, provider_key,
          options.merge({
            :application => application,
            :event => event,
            :description => message
          })
        )
      end
    end

    # Verify the configured API key is valid
    def verify
      raise ConfigurationError, "You must provide an API key to verify" if api_key.nil?
      perform(:verify, api_key, provider_key, {}, :get)
    end

    def perform(command, api_key, provider_key, data = {}, method = :post) #:nodoc:
      params = { :apikey => format_api_key(command, api_key), :provider_key => provider_key }.merge(data).delete_if { |k,v| v.nil? }
      case method
      when :post
        perform_post(command, params)
      else
        perform_get(command, params)
      end
    end

    def enqueue_delayed_job(config, event, message, options) #:nodoc:
      record = Delayed::Job.enqueue(DelayedJob.new do |job|
        job.api_key = config.api_key
        job.provider_key = config.provider_key
        job.application = config.application
        job.event = event
        job.message = message
        job.priority = options[:priority] || Priority::NORMAL
        job.url = options[:url]
      end)
      !record.new_record?
    end

    private
      def headers(extra_headers = {}) #:nodoc:
        { 'User-Agent' => USER_AGENT }.merge(extra_headers)
      end

      def perform_get(command, params) #:nodoc:
        url = URI.parse("#{SERVICE_URL}/#{command}?#{params.map{ |k,v| %(#{URI.encode(k.to_s)}=#{URI.encode(v.to_s)}) }.join('&')}")
        request = Net::HTTP::Get.new("#{url.path}?#{url.query}", headers)
        perform_request(url, request)
      end

      def perform_post(command, params) #:nodoc:
        url = URI.parse("#{SERVICE_URL}/#{command}")
        request = Net::HTTP::Post.new(url.path, headers)
        request.form_data = params
        perform_request(url, request)
      end

      def perform_request(url, request) #:nodoc:
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        if verify_certificate?
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          http.ca_file = root_certificates
        else
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end
        http.read_timeout = read_timeout
        http.open_timeout = open_timeout
        http.start do
          begin
            return true unless send_notifications
            response = http.request(request)
            case response
            when Net::HTTPSuccess then
              logger.info "Prowl Success: #{response.class}"
              true
            else
              logger.error "Prowl Failure: #{response.class}\n#{response.body if response.respond_to? :body}"
              false
            end
          rescue TimeoutError => e
            logger.error "Timeout while contacting the Prowl server."
            false
          end
        end
      end

      def format_api_key(command, api_key)
        if api_key.is_a?(Array)
          MULTIPLE_APIKEY_COMMANDS.include?(command.to_s) ? api_key.join(",") : api_key.first.to_s
        else
          api_key.to_s
        end
      end
  end

  attr_accessor :api_key, :provider_key #:nodoc:
  attr_accessor :application, :send_notifications #:nodoc:

  # Create an instance for sending to different accounts within a single Rails application
  # * api_key:      Your API key.
  # * application:  The name of your application.
  # * provider_key: Key to override the rate limit of 1000 requests per hour. (Optional)
  def initialize(api_key, application, provider_key = nil)
    @api_key, @application, @provider_key = api_key, application, provider_key
  end

  # Send a notification to your iPhone:
  # * event:    The title of notification you want to send.
  # * message:  The text of the notification message you want to send.
  #
  # The following options are supported:
  # * +:delayed+:  Whether to use Delayed::Job to send notifications. (Optional)
  # * +:priority+: The priority of the notification - see Prowler::Priority. (Optional)
  # * +:url+:      A custom url for the Prowl application to open. (Optional)
  def notify(event, message, *args)
    raise ConfigurationError, "You must provide an API key to send notifications" if api_key.nil?
    raise ConfigurationError, "You must provide an application name to send notifications" if application.nil?

    if args.first.is_a?(Hash)
      options = args.first
      options[:priority] ||= Priority::NORMAL
      options[:delayed] ||= self.class.delayed
    else
      options = {
        :priority => args.shift || Priority::NORMAL,
        :delayed => args.shift || self.class.delayed
      }
    end

    if options.delete(:delayed)
      self.class.enqueue_delayed_job(self, event, message, options)
    else
      self.class.perform(
        :add, api_key, provider_key,
        options.merge({
          :application => application,
          :event => event,
          :description => message
        })
      )
    end
  end

  # Verify the configured API key is valid
  def verify
    raise ConfigurationError, "You must provide an API key to verify" if api_key.nil?
    self.class.perform(:verify, api_key, provider_key, {}, :get)
  end
end

require 'prowler/railtie' if defined?(Rails::Railtie)
require 'prowler/version'
