require 'prowler/configuration'
require 'prowler/delayed_job'
require 'prowler/priority'
require 'prowler/version'

module Prowler

  SERVICE_URL = "https://prowlapp.com/publicapi"
  USER_AGENT = "Prowler/#{VERSION}"
  MULTIPLE_APIKEY_COMMANDS = %w(add)
  CONFIG_ATTRS = [:application, :provider_key, :api_key]

  class ConfigurationError < StandardError; end

  class Application
    attr_accessor :api_key, :provider_key #:nodoc:
    attr_accessor :application, :send_notifications #:nodoc:

    # Create an instance for sending to different accounts within a single Rails application
    # Pass any of the following options to override the global configuration:
    # * +:application+:  The name of your application.
    # * +:provider_key+: Key to override the rate limit of 1000 requests per hour.
    # * +:api_key+:      Your API key.
    def initialize(*args)
      if args.empty?
        CONFIG_ATTRS.each{ |attr| send("#{attr}=".to_sym, Prowler.send(attr)) }
      elsif args.first.is_a?(Hash)
        CONFIG_ATTRS.each do |attr|
          send("#{attr}=".to_sym, args[0][attr] || Prowler.send(attr))
        end
      else
        @api_key, @application, @provider_key = args[0], args[1], args[2]
      end
    end

    # Send a notification to your iPhone:
    # * event:   The title of notification you want to send.
    # * message: The text of the notification message you want to send.
    # * api_key: One or more API keys to be notified - uses the configured key(s) if not provided.
    #
    # The following options are supported:
    # * +:delayed+:  Whether to use Delayed::Job to send notifications.
    # * +:priority+: The priority of the notification - see Prowler::Priority.
    # * +:url+:      A custom url for the Prowl application to open.
    def notify(event, message, *args)
      api_key = args.first.is_a?(String) || args.first.is_a?(Array) ? args.shift : self.api_key

      raise ConfigurationError, "You must provide an API key to send notifications" if api_key.nil?
      raise ConfigurationError, "You must provide an application name to send notifications" if application.nil?

      if args.first.is_a?(Fixnum)
        options = { :priority => args.shift, :delayed => args.shift || Prowler.delayed }
      else
        options = args.last.is_a?(Hash) ? args.pop : {}
        options = { :priority => Prowler::Priority::NORMAL, :delayed => Prowler.delayed }.merge(options)
      end

      options.merge!(
        :application => application, :providerkey => provider_key,
        :apikey => api_key, :event => event, :description => message
      )

      if options.delete(:delayed)
        enqueue_delayed_job(options)
      else
        perform(:add, options)
      end
    end

    # Verify the configured API key is valid
    def verify(api_key = nil)
      raise ConfigurationError, "You must provide an API key to verify" if api_key.nil? && self.api_key.nil?
      perform(:verify, { :providerkey => provider_key, :apikey => api_key || self.api_key }, :get)
    end

    private
      def perform(command, params = {}, method = :post) #:nodoc:
        params[:apikey] = format_api_key(command, params[:apikey]) if params.key?(:apikey)
        params.delete_if { |k,v| v.nil? }

        case method
        when :post
          perform_post(command, params)
        else
          perform_get(command, params)
        end
      end

      def enqueue_delayed_job(options) #:nodoc:
        record = Delayed::Job.enqueue(Prowler::DelayedJob.new do |job|
          job.api_key = options[:apikey]
          job.provider_key = options[:providerkey]
          job.application = options[:application]
          job.event = options[:event]
          job.message = options[:description]
          job.priority = options[:priority]
          job.url = options[:url]
        end)
        !record.new_record?
      end

      def headers(extra_headers = {}) #:nodoc:
        { 'User-Agent' => USER_AGENT }.merge(extra_headers)
      end

      def logger #:nodoc:
        Prowler.logger
      end

      def verify_certificate? #:nodoc:
        Prowler.verify_certificate?
      end

      def root_certificates #:nodoc:
        Prowler.root_certificates
      end

      def send_notifications #:nodoc:
        @send_notifications.nil? ? true : !!@send_notifications
      end

      def send_notifications? #:nodoc:
        send_notifications && Prowler.send_notifications
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
        http.read_timeout = Prowler.read_timeout
        http.open_timeout = Prowler.open_timeout
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

      def format_api_key(command, api_key) #:nodoc:
        if api_key.is_a?(Array)
          MULTIPLE_APIKEY_COMMANDS.include?(command.to_s) ? api_key.join(",") : api_key.first.to_s
        else
          api_key.to_s
        end
      end
  end
end
