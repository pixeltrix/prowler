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
require 'net/https'
require 'uri'

module Prowler

  SERVICE_URL = "https://prowl.weks.net/publicapi"
  USER_AGENT = "Prowler/1.0.3"

  module Priority
    VERY_LOW  = -2
    MODERATE  = -1
    NORMAL    = 0
    HIGH      = 1
    EMERGENCY = 2
  end

  class << self
    attr_accessor :api_key
    attr_accessor :application, :send_notifications

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
      @application = @api_key = nil
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

    # Send a notification to your iPhone:
    # * event:    The title of notification you want to send.
    # * message:  The text of the notification message you want to send.
    # * priority: The priority of the notification - see Prowler::Priority. (Optional)
    def notify(event, message, priority = Priority::NORMAL)
      raise RuntimeError, "Prowler needs to be configured first before using it" unless configured?

      url = URI.parse(SERVICE_URL)
      http = Net::HTTP.new(url.host, url.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.start do
        headers = {
          'User-Agent' => USER_AGENT
        }
        http.read_timeout = 5 # seconds
        http.open_timeout = 2 # seconds
        request = Net::HTTP::Post.new("#{url.path}/add", headers)
        request.set_form_data({ 'apikey' => api_key, 'priority' => priority, 'application' => application, 'event' => event, 'description' => message })
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

    # Verify the configured API key is valid
    def verify
      raise RuntimeError, "Prowler needs to be configured first before using it" unless api_key

      url = URI.parse(SERVICE_URL)
      http = Net::HTTP.new(url.host, url.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.start do
        headers = {
          'User-Agent' => USER_AGENT
        }
        http.read_timeout = 5 # seconds
        http.open_timeout = 2 # seconds
        request = Net::HTTP::Get.new("#{url.path}/verify?apikey=#{api_key}", headers)
        response = begin
                     http.request(request) if send_notifications?
                   rescue TimeoutError => e
                     logger.error "Timeout while contacting the Prowl server."
                     nil
                   end
        case response
        when Net::HTTPSuccess then
          logger.info "Prowl Success: #{response.class}"
          true
        else
          logger.error "Prowl Failure: #{response.class}\n#{response.body if response.respond_to? :body}"
          false
        end
      end
    end
  end
end
