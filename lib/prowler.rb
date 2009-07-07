require 'logger'
require 'net/http'
require 'net/https'

module Prowler
  class << self
    attr_accessor :host, :port, :secure
    attr_accessor :username, :password
    attr_accessor :application, :send_notifications

    # The host to connect to.
    def host
      @host ||= 'prowl.weks.net'
    end

    # The port on which the service runs.
    def port
      @port || (secure ? 443 : 80)
    end

    # Whether the service is running over SSL.
    def secure
      @secure.nil? ? true : !!@secure
    end

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
      @host = @port = @secure = @application = @username = @password = nil
    end

    # Whether the library has been configured
    def configured?
      !(@application.nil? || @username.nil? || @password.nil?)
    end

    def path(*params) #:nodoc:
      sprintf("/api/add_notification.php?application=%s&event=%s&description=%s", *params)
    end

    # Returns the default logger or a logger that prints to STDOUT.
    def logger
      ActiveRecord::Base.logger
    rescue
      @logger ||= Logger.new(STDERR)
    end

    # Send a notification to your iPhone:
    # * event: The title of notification you want to send.
    # * message: The text of the notification message you want to send.
    def notify(event, message)
      raise RuntimeError, "Prowler needs to be configured first before using it" unless configured?

      http = Net::HTTP.new(host, port)
      http.use_ssl = secure
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.start do
        headers = {
          'User-Agent' => 'ProwlScript/1.0'
        }
        http.read_timeout = 5 # seconds
        http.open_timeout = 2 # seconds
        request = Net::HTTP::Get.new(path(URI.escape(application), URI.escape(event), URI.escape(message)), headers)
        request.basic_auth(username, password)
        response = begin
                     http.request(request) if send_notifications?
                   rescue TimeoutError => e
                     logger.error "Timeout while contacting the Prowl server."
                     nil
                   end
        case response
        when Net::HTTPSuccess then
          logger.info "Prowl Success: #{response.class}"
        when NilClass then
          # Do nothing
        else
          logger.error "Prowl Failure: #{response.class}\n#{response.body if response.respond_to? :body}"
        end
      end
    end
  end
end
