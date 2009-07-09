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
# === About
#
# Prowler relies upon the Prowl iPhone application which is advertised as
# a Growl notification forwarder from your Mac. However they provide an API
# which can be called by a generic script which allows you to use the
# application as a general push notification application for your iPhone.
#
# For more about the Prowl application see: http://prowl.weks.net/

require 'logger'
require 'net/http'
require 'net/https'

module Prowler

  API_PATH = "/publicapi/add"
  DEPRECATED_API_PATH = "/api/add_notification.php?application=%s&event=%s&description=%s"
  USER_AGENT = "Prowler/1.0.3"

  module Priority
    VERY_LOW  = -2
    MODERATE  = -1
    NORMAL    = 0
    HIGH      = 1
    EMERGENCY = 2
  end

  class << self
    attr_accessor :host, :port, :secure
    attr_accessor :api_key, :username, :password
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

    def username=(value) #:nodoc:
      logger.warn "The username/password API has been deprecated please switch to using an API key."
      @username = value
    end

    # Whether to send notifications
    def send_notifications
      @send_notifications.nil? ? true : !!@send_notifications
    end
    alias :send_notifications? :send_notifications

    # Reset configuration
    def reset_configuration
      @host = @port = @secure = @application = @username = @password = @api_key = nil
    end

    # Whether the library has been configured
    def configured?
      !@application.nil? && (!@api_key.nil? || !(@username.nil? || @password.nil?))
    end

    # Returns the default logger or a logger that prints to STDOUT.
    def logger
      ActiveRecord::Base.logger
    rescue
      @logger ||= Logger.new(STDERR)
    end

    # Send a notification to your iPhone:
    # * event:    The title of notification you want to send.
    # * message:  The text of the notification message you want to send.
    # * priority: The priority of the notification - see Prowler::Priority. (Optional)
    def notify(event, message, priority = Priority::NORMAL)
      raise RuntimeError, "Prowler needs to be configured first before using it" unless configured?

      http = Net::HTTP.new(host, port)
      http.use_ssl = secure
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.start do
        headers = {
          'User-Agent' => USER_AGENT
        }
        http.read_timeout = 5 # seconds
        http.open_timeout = 2 # seconds
        if api_key
          request = Net::HTTP::Post.new(API_PATH, headers)
          request.set_form_data({ 'apikey' => api_key, 'priority' => priority, 'application' => application, 'event' => event, 'description' => message })
        else
          request = Net::HTTP::Get.new(sprintf(DEPRECATED_API_PATH, URI.escape(application), URI.escape(event), URI.escape(message)), headers)
          request.basic_auth(username, password)
        end
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
