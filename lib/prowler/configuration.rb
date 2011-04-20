module Prowler
  class << self
    attr_accessor :service_url, :api_key, :provider_key
    attr_accessor :application, :send_notifications
    attr_accessor :read_timeout, :open_timeout #:nodoc:
    attr_accessor :delayed, :verify_certificate, :root_certificates
    attr_accessor :raise_errors

    # Call this method to configure your account details in an initializer.
    def configure
      yield self
    end

    def service_url #:nodoc:
      @service_url ||= SERVICE_URL
    end

    def send_notifications #:nodoc:
      @send_notifications.nil? ? true : !!@send_notifications
    end

    def delayed #:nodoc:
      @delayed.nil? ? false : !!@delayed
    end

    def raise_errors #:nodoc:
      @raise_errors.nil? ? false : !!@raise_errors
    end

    # Reset configuration
    def reset_configuration
      @service_url = @application = @api_key = @provider_key = nil
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
    # Default: #{Rails.root}/config/cacert.pem
    def root_certificates
      if defined?(Rails.root)
        @root_certificates ||= File.expand_path('config/cacert.pem', Rails.root)
      elsif defined?(RAILS_ROOT)
        @root_certificates ||= File.expand_path('config/cacert.pem', RAILS_ROOT)
      else
        @root_certificates ||= File.expand_path('../config/cacert.pem', __FILE__)
      end
    end

    # Returns the default logger or a logger that prints to STDOUT.
    def logger
      @logger ||= rails_logger
    end

    # Override the default logger
    def logger=(new_logger)
      @logger = new_logger
    end

    def rails_logger #:nodoc:
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
  end
end