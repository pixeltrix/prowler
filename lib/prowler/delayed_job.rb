module Prowler
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
end