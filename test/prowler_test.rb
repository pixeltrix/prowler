require 'test/unit'
require 'rubygems'
require 'mocha'
require 'shoulda'
require 'webmock/test_unit'
require File.expand_path('../../lib/prowler', __FILE__)

class FakeLogger
  def info(*args); end
  def debug(*args); end
  def warn(*args); end
  def error(*args); end
  def fatal(*args); end
end

RAILS_ROOT = File.dirname(__FILE__)
RAILS_DEFAULT_LOGGER = FakeLogger.new

class ProwlerTest < Test::Unit::TestCase
  context "Prowler configuration" do
    setup do
      Prowler.reset_configuration
    end

    should "be done with a block" do
      Prowler.configure do |config|
        config.api_key = "apikey"
        config.application = "application"
        config.provider_key = "providerkey"
      end

      assert_equal "apikey",      Prowler.api_key
      assert_equal "application", Prowler.application
      assert_equal "providerkey", Prowler.provider_key
    end

    should "not set a default application" do
      assert_equal nil, Prowler.application
    end

    should "not set a default API key" do
      assert_equal nil, Prowler.api_key
    end

    context "when using an instance" do
      setup do
        Prowler.reset_configuration

        Prowler.configure do |config|
          config.api_key = "apikey"
          config.application = "application"
          config.provider_key = "providerkey"
        end
      end

      should "inheirit config from global scope" do
        prowler = Prowler.new
        assert_equal "apikey",      prowler.api_key
        assert_equal "application", prowler.application
        assert_equal "providerkey", prowler.provider_key
      end

      should "override application config" do
        prowler = Prowler.new(:application => "application2")
        assert_equal "application2", prowler.application
      end

      should "override provider_key config" do
        prowler = Prowler.new(:provider_key => "providerkey2")
        assert_equal "providerkey2", prowler.provider_key
      end

      should "override api_key config" do
        prowler = Prowler.new(:api_key => "apikey2")
        assert_equal "apikey2", prowler.api_key
      end
    end
  end

  context "Sending a notification" do
    setup do
      Prowler.reset_configuration
      Prowler.configure do |config|
        config.api_key = "apikey"
        config.application = "Application Name"
      end
    end

    should "raise an exception if API key not configured" do
      Prowler.reset_configuration
      assert_raises Prowler::ConfigurationError do
        Prowler.notify("Event", "Description")
      end

      prowler = Prowler.new(nil, nil)
      assert_raises Prowler::ConfigurationError do
        prowler.notify("Event", "Description")
      end
    end

    should "raise an exception if application not configured" do
      Prowler.reset_configuration
      Prowler.configure do |config|
        config.api_key = "apikey"
      end
      assert_raises Prowler::ConfigurationError do
        Prowler.notify("Event", "Description", Prowler::Priority::NORMAL)
      end

      prowler = Prowler.new("apikey", nil)
      assert_raises Prowler::ConfigurationError do
        prowler.notify("Event", "Description", Prowler::Priority::NORMAL)
      end
    end

    should "verify SSL certificates by default" do
      Net::HTTP.any_instance.expects(:use_ssl=).with(true)
      Net::HTTP.any_instance.expects(:verify_mode=).with(OpenSSL::SSL::VERIFY_PEER)
      Net::HTTP.any_instance.expects(:ca_file=).with(File.expand_path('config/cacert.pem', RAILS_ROOT))

      Prowler.send_notifications = false
      Prowler.notify("Event Name", "Message Text")
    end

    should "not verify SSL certificates if verification is turned off" do
      Net::HTTP.any_instance.expects(:use_ssl=).with(true)
      Net::HTTP.any_instance.expects(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)

      Prowler.send_notifications = false
      Prowler.verify_certificate = false
      Prowler.notify("Event Name", "Message Text")
    end

    should "not send notifications if send_notifications is false" do
      Prowler.send_notifications = false
      assert_not_notified Prowler, "Event Name", "Message Text"
    end

    should "send multiple API keys if configured" do
      Prowler.api_key = %w(apikey1 apikey2)
      assert_notified Prowler, "Event Name", "Message Text"
    end

    should "log a successful response" do
      Prowler.logger.expects(:info).with("Prowl Success: Net::HTTPOK")
      assert_notified Prowler, "Event Name", "Message Text"
    end

    should "log an error response" do
      Prowler.logger.expects(:error).with("Prowl Failure: Net::HTTPInternalServerError\n")
      assert_notified Prowler, "Event Name", "Message Text" do |request|
        request.to_return(:status => 500, :body => "", :headers => {})
      end
    end

    should "delay sending if configured globally" do
      Prowler.delayed = true
      assert_delayed Prowler, "Event Name", "Message Text"
    end

    should "delay sending using options" do
      Prowler.delayed = false
      assert_delayed Prowler, "Event Name", "Message Text", :delayed => true
    end

    should "send a custom url" do
      assert_notified Prowler, "Event Name", "Message Text", :url => "http://www.pixeltrix.co.uk"
    end

    should "send with a high priority using options" do
      assert_notified Prowler, "Event Name", "Message Text", :priority => Prowler::Priority::HIGH
    end

    should "send the provider key if configured" do
      Prowler.provider_key = "providerkey"
      assert_notified Prowler, "Event Name", "Message Text"
    end
  end

  context "Verifying an API key" do
    setup do
      Prowler.reset_configuration
      Prowler.configure do |config|
        config.api_key = "apikey"
        config.application = "Application Name"
      end
    end

    should "raise an exception if API key not configured" do
      Prowler.reset_configuration
      assert_raises Prowler::ConfigurationError do
        Prowler.verify
      end

      prowler = Prowler.new(nil, nil)
      assert_raises Prowler::ConfigurationError do
        Prowler.verify
      end
    end

    should "only verify the first API key" do
      Prowler.api_key = %w(apikey1 apikey2)
      assert_verified Prowler, "apikey1"
    end

    should "not send notifications if send_notifications is false" do
      Prowler.send_notifications = false
      assert_not_verified Prowler
    end

    should "verify SSL certificates by default" do
      Net::HTTP.any_instance.expects(:use_ssl=).with(true)
      Net::HTTP.any_instance.expects(:verify_mode=).with(OpenSSL::SSL::VERIFY_PEER)
      Net::HTTP.any_instance.expects(:ca_file=).with(File.expand_path('config/cacert.pem', RAILS_ROOT))

      Prowler.send_notifications = false
      Prowler.verify
    end

    should "not verify SSL certificates if verification is turned off" do
      Net::HTTP.any_instance.expects(:use_ssl=).with(true)
      Net::HTTP.any_instance.expects(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)

      Prowler.send_notifications = false
      Prowler.verify_certificate = false
      Prowler.verify
    end

    should "send the provider key if configured" do
      Prowler.provider_key = "providerkey"
      assert_verified Prowler, "apikey", "providerkey"
    end
  end

  context "Using deprecated API" do
    context "Prowler configuration" do
      setup do
        Prowler.reset_configuration
      end

      should "override class configuration when using an instance" do
        prowler = Prowler.new("apikey2", "application2", "providerkey2")
        assert_equal "apikey2",      prowler.api_key
        assert_equal "application2", prowler.application
        assert_equal "providerkey2", prowler.provider_key
      end
    end

    context "Sending a notification" do
      setup do
        Prowler.reset_configuration
        Prowler.configure do |config|
          config.api_key = "apikey"
          config.application = "Application Name"
        end
      end

      should "raise an exception if API key not configured" do
        Prowler.reset_configuration
        assert_raises Prowler::ConfigurationError do
          Prowler.notify("Event", "Description")
        end

        prowler = Prowler.new(nil, nil)
        assert_raises Prowler::ConfigurationError do
          prowler.notify("Event", "Description")
        end
      end

      should "raise an exception if application not configured" do
        Prowler.reset_configuration
        Prowler.configure do |config|
          config.api_key = "apikey"
        end
        assert_raises Prowler::ConfigurationError do
          Prowler.notify("Event", "Description", Prowler::Priority::NORMAL)
        end

        prowler = Prowler.new("apikey", nil)
        assert_raises Prowler::ConfigurationError do
          prowler.notify("Event", "Description", Prowler::Priority::NORMAL)
        end
      end

      should "delay sending using parameter" do
        Prowler.delayed = false
        assert_delayed Prowler, "Event Name", "Message Text", Prowler::Priority::NORMAL, true
      end

      should "send with a high priority using parameter" do
        assert_notified Prowler, "Event Name", "Message Text", Prowler::Priority::HIGH
      end
    end

    context "Verifying an API key" do
      setup do
        Prowler.reset_configuration
        Prowler.configure do |config|
          config.api_key = "apikey"
          config.application = "Application Name"
        end
      end

      should "raise an exception if API key not configured" do
        Prowler.reset_configuration
        assert_raises Prowler::ConfigurationError do
          Prowler.verify
        end

        prowler = Prowler.new(nil, nil)
        assert_raises Prowler::ConfigurationError do
          Prowler.verify
        end
      end
    end
  end

  private
    def verify_url
      "#{Prowler::SERVICE_URL}/verify"
    end

    def build_url(config, api_key, provider_key)
      if provider_key
        "#{verify_url}?providerkey=#{provider_key}&apikey=#{api_key}"
      else
        "#{verify_url}?apikey=#{api_key}"
      end
    end

    def assert_verified(config, api_key = "apikey", provider_key = nil, &block)
      request = stub_request(:get, build_url(config, api_key, provider_key))
      request.with(:headers => { "Accept" => "*/*" })
      request.with(:headers => { "User-Agent" => Prowler::USER_AGENT })

      if block_given?
        yield request
      else
        request.to_return(:status => 200, :body => "", :headers => {})
      end

      config.verify
      assert_requested :get, build_url(config, api_key, provider_key)
    end

    def assert_not_verified(config, api_key = "apikey", provider_key = nil)
      config.verify
      assert_not_requested :get, build_url(config, api_key, provider_key)
    end

    def notify_url
      "#{Prowler::SERVICE_URL}/add"
    end

    def build_request(config, event, message, options)
      body = {}
      if options.is_a?(Hash)
        body["priority"] = (options[:priority] || Prowler::Priority::NORMAL).to_s
        body["url"] = options[:url] if options[:url]
      else
        body["priority"] = (options || Prowler::Priority::NORMAL).to_s
      end
      body["application"] = config.application
      body["event"] = event
      body["apikey"] = Array(config.api_key).join(",")
      body["description"] = message
      body["providerkey"] = config.provider_key if config.provider_key
      body
    end

    def assert_notified(config, event, message, options = {}, &block)
      body = build_request(config, event, message, options)

      request = stub_request(:post, notify_url)
      request.with(:headers => { "Accept" => "*/*" })
      request.with(:headers => { "User-Agent" => Prowler::USER_AGENT })
      request.with(:headers => { "Content-Type" => "application/x-www-form-urlencoded" })
      request.with(:body => body)

      if block_given?
        yield request
      else
        request.to_return(:status => 200, :body => "", :headers => {})
      end

      config.notify event, message, options
      assert_requested :post, notify_url, :body => body
    end

    def assert_not_notified(config, event, message, options = {})
      config.notify event, message
      assert_not_requested :post, notify_url, :body => build_request(config, event, message, options)
    end

    def assert_delayed(config, event, message, *args, &block)
      if args.first.is_a?(Hash) || args.empty?
        options = args.first || {}
        delayed = options.delete(:delayed)
        options[:priority] ||= Prowler::Priority::NORMAL

        Prowler::Application.any_instance.expects(:enqueue_delayed_job).with("Event Name", "Message Text", options)
        config.notify event, message, options.merge(:delayed => delayed)
      else
        priority = args.shift
        delayed = args.shift
        options = { :priority => priority }

        Prowler::Application.any_instance.expects(:enqueue_delayed_job).with("Event Name", "Message Text", options)
        config.notify event, message, priority, delayed
      end

      if delayed
        assert_not_requested :post, notify_url, :body => build_request(config, event, message, options)
      end
    end

end
