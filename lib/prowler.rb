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
  USER_AGENT = "Prowler/1.0.3"

  module Priority
    VERY_LOW  = -2
    MODERATE  = -1
    NORMAL    = 0
    HIGH      = 1
    EMERGENCY = 2
  end

  class ConfigurationError < StandardError; end

  class << self
    attr_accessor :api_key, :provider_key
    attr_accessor :application, :send_notifications
    attr_accessor :read_timeout, :open_timeout

    # Call this method to configure your account details in an initializer.
    def configure
      yield self
    end

    # Whether to send notifications
    def send_notifications
      @send_notifications.nil? ? true : !!@send_notifications
    end
    alias :send_notifications? :send_notifications

    # Reset configuration
    def reset_configuration
      @application = @api_key = @provider_key = nil
    end

    # Whether the library has been configured
    def configured?
      !@application.nil? && !@api_key.nil?
    end

    # Returns the default logger or a logger that prints to STDOUT.
    def logger
      ActiveRecord::Base.logger
    rescue
      @logger ||= Logger.new(STDERR)
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
    # * priority: The priority of the notification - see Prowler::Priority. (Optional)
    def notify(event, message, priority = Priority::NORMAL)
      raise ConfigurationError, "You must provide an API key to send notifications" if api_key.nil?
      raise ConfigurationError, "You must provide an application name to send notifications" if application.nil?
      perform(
        :add, api_key, provider_key,
        {
          :application => application,
          :event => event,
          :description => message,
          :priority => priority
        }
      )
    end

    # Verify the configured API key is valid
    def verify
      raise ConfigurationError, "You must provide an API key to verify" if api_key.nil?
      perform(:verify, api_key, provider_key, {}, :get)
    end

    def perform(command, api_key, provider_key, data = {}, method = :post) #:nodoc:
      params = { :apikey => api_key, :provider_key => provider_key }.merge(data).delete_if { |k,v| v.nil? }
      case method
      when :post
        perform_post(command, params)
      else
        perform_get(command, params)
      end
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
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.read_timeout = read_timeout
        http.open_timeout = open_timeout
        http.start do
          begin
            return true unless send_notifications?
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
  end

  attr_accessor :api_key, :provider_key
  attr_accessor :application, :send_notifications

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
  # * priority: The priority of the notification - see Prowler::Priority. (Optional)
  def notify(event, message, priority = Priority::NORMAL)
    raise ConfigurationError, "You must provide an API key to send notifications" if api_key.nil?
    raise ConfigurationError, "You must provide an application name to send notifications" if application.nil?
    self.class.perform(
      :add, api_key, provider_key,
      {
        :application => application,
        :event => event,
        :description => message,
        :priority => priority
      }
    )
  end

  # Verify the configured API key is valid
  def verify
    raise ConfigurationError, "You must provide an API key to verify" if api_key.nil?
    self.class.perform(:verify, api_key, provider_key, {}, :get)
  end
end
