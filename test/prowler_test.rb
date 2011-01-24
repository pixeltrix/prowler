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
      end

      assert_equal "apikey",      Prowler.api_key
      assert_equal "application", Prowler.application
    end

    should "not set a default application" do
      assert_equal nil, Prowler.application
    end

    should "not set a default API key" do
      assert_equal nil, Prowler.api_key
    end

    should "override class configuration when using an instance" do
      prowler = Prowler.new("apikey2", "application2")
      assert_equal "apikey2",      prowler.api_key
      assert_equal "application2", prowler.application
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
      Net::HTTP.any_instance.expects(:ca_file=).with(File.join(RAILS_ROOT, "config", "cacert.pem"))

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
      Net::HTTP.any_instance.expects(:ca_file=).with(File.join(RAILS_ROOT, "config", "cacert.pem"))

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
  end

  private
    def verify_url
      "https://prowl.weks.net/publicapi/verify"
    end

    def assert_verified(config, api_key = "apikey", &block)
      request = stub_request(:get, "#{verify_url}?apikey=#{api_key}")
      request.with(:headers => { "Accept" => "*/*" })
      request.with(:headers => { "User-Agent" => Prowler::USER_AGENT })

      if block_given?
        yield request
      else
        request.to_return(:status => 200, :body => "", :headers => {})
      end

      config.verify
      assert_requested :get, "#{verify_url}?apikey=#{api_key}"
    end

    def assert_not_verified(config, api_key = "apikey")
      config.verify
      assert_not_requested :get, "#{verify_url}?apikey=#{api_key}"
    end

    def notify_url
      "https://prowl.weks.net/publicapi/add"
    end

    def build_request(config, event, message, options)
      body = {}
      body["priority"] = (options[:priority] || Prowler::Priority::NORMAL).to_s
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

      config.notify event, message
      assert_requested :post, notify_url, :body => body
    end

    def assert_not_notified(config, event, message, options = {})
      config.notify event, message
      assert_not_requested :post, notify_url, :body => build_request(config, event, message, options)
    end

end
