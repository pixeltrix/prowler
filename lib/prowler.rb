# Prowler is a plugin for integrating apps with the Prowl iPhone application.
#
# === Installation
#
# From your application root, run:
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
# this rake task (from your application root):
#
#   rake prowler:test
#
# If everything is configured properly the task will send a request to
# prowlapp.com which will be appear on your iPhone after a short delay.
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
#   prowler = Prowler.new(:application => 'application', :api_key => 'apikey')
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
# For more about the Prowl application see: http://prowlapp.com/

require 'logger'
require 'net/https'
require 'rexml/document'
require 'uri'

require 'prowler/application'
require 'prowler/railtie' if defined?(Rails::Railtie)

module Prowler
  class << self
    # Send a notification to your iPhone:
    # * event:   The title of notification you want to send.
    # * message: The text of the notification message you want to send.
    # * api_key: One or more API keys to be notified - uses the configured key(s) if not provided.
    #
    # The following options are supported:
    # * :delayed:  Whether to use Delayed::Job to send notifications. (Optional)
    # * :priority: The priority of the notification - see Prowler::Priority. (Optional)
    # * :url:      A custom url for the Prowl application to open. (Optional)
    def notify(event, message, *args)
      new.notify(event, message, *args)
    end

    # Verify the configured API key is valid
    # * api_key: API key to be verified - uses the first configured key(s) if not provided.
    def verify(api_key = nil)
      new.verify(api_key)
    end

    # Retrieve a registration token and confirmation url for the initial phase
    # of fetching an API key for a user. The token is valid for 24 hours.
    # This API command requires the provider_key to be configured.
    #
    # Returns either Prowler::Token object if successful or nil if an error occurs.
    def retrieve_token
      new.retrieve_token
    end

    # Retrieve an API key for a user using the token provided by retrieve_token.
    # This API command requires the provider_key to be configured.
    # * token: Token returned by retrieve_token command.
    #
    # Returns either Prowler::ApiKey object if successful or nil if an error occurs.
    def retrieve_api_key(token)
      new.retrieve_api_key(token)
    end

    # Create an instance for sending to different accounts within a single Rails application
    # Pass any of the following options to override the global configuration:
    # * :application:  The name of your application.
    # * :provider_key: Key to override the rate limit of 1000 requests per hour.
    # * :api_key:      Your API key.
    def new(*args)
      Prowler::Application.new(*args)
    end
  end
end
