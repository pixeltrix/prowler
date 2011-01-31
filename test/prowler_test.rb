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
        Prowler.notify "Event", "Description"
      end

      prowler = Prowler.new(nil, nil)
      assert_raises Prowler::ConfigurationError do
        prowler.notify "Event", "Description"
      end
    end

    should "raise an exception if application not configured" do
      Prowler.reset_configuration
      Prowler.configure do |config|
        config.api_key = "apikey"
      end
      assert_raises Prowler::ConfigurationError do
        Prowler.notify "Event", "Description"
      end

      prowler = Prowler.new("apikey", nil)
      assert_raises Prowler::ConfigurationError do
        prowler.notify "Event", "Description"
      end
    end

    should "verify SSL certificates by default" do
      Net::HTTP.any_instance.expects(:use_ssl=).with(true)
      Net::HTTP.any_instance.expects(:verify_mode=).with(OpenSSL::SSL::VERIFY_PEER)
      Net::HTTP.any_instance.expects(:ca_file=).with(File.expand_path('config/cacert.pem', RAILS_ROOT))

      Prowler.send_notifications = false
      Prowler.notify "Event Name", "Message Text"
    end

    should "not verify SSL certificates if verification is turned off" do
      Net::HTTP.any_instance.expects(:use_ssl=).with(true)
      Net::HTTP.any_instance.expects(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)

      Prowler.send_notifications = false
      Prowler.verify_certificate = false
      Prowler.notify "Event Name", "Message Text"
    end

    should "not send notifications if send_notifications is false" do
      stub_request :post, "#{Prowler::SERVICE_URL}/add"

      Prowler.send_notifications = false
      Prowler.notify "Event Name", "Message Text"

      assert_not_requested :post, "#{Prowler::SERVICE_URL}/add"
    end

    should "send multiple API keys if configured" do
      stub_request :post, "#{Prowler::SERVICE_URL}/add"

      Prowler.api_key = %w(apikey1 apikey2)
      Prowler.notify "Event Name", "Message Text"

      assert_requested :post, "#{Prowler::SERVICE_URL}/add", :body => {
        :application => "Application Name",
        :apikey => "apikey1,apikey2",
        :event => "Event Name",
        :description => "Message Text",
        :priority => Prowler::Priority::NORMAL.to_s
      }
    end

    should "log a successful response" do
      stub_request :post, "#{Prowler::SERVICE_URL}/add"

      Prowler.logger.expects(:info).with("Prowl Success: Net::HTTPOK")
      Prowler.notify "Event Name", "Message Text"

      assert_requested :post, "#{Prowler::SERVICE_URL}/add", :body => {
        :application => "Application Name",
        :apikey => "apikey",
        :event => "Event Name",
        :description => "Message Text",
        :priority => Prowler::Priority::NORMAL.to_s
      }
    end

    should "log an error response" do
      stub_request(:post, "#{Prowler::SERVICE_URL}/add").
        to_return(:status => 500, :body => "", :headers => {})

      Prowler.logger.expects(:error).with("Prowl Failure: Net::HTTPInternalServerError\n")
      Prowler.notify "Event Name", "Message Text"

      assert_requested :post, "#{Prowler::SERVICE_URL}/add", :body => {
        :application => "Application Name",
        :apikey => "apikey",
        :event => "Event Name",
        :description => "Message Text",
        :priority => Prowler::Priority::NORMAL.to_s
      }
    end

    should "delay sending if configured globally" do
      Prowler::Application.any_instance.expects(:enqueue_delayed_job).with(
        :application => "Application Name",
        :providerkey => nil,
        :apikey => "apikey",
        :event => "Event Name",
        :description => "Message Text",
        :priority => Prowler::Priority::NORMAL
      )

      Prowler.delayed = true
      Prowler.notify "Event Name", "Message Text"
    end

    should "delay sending using options" do
      Prowler::Application.any_instance.expects(:enqueue_delayed_job).with(
        :application => "Application Name",
        :providerkey => nil,
        :apikey => "apikey",
        :event => "Event Name",
        :description => "Message Text",
        :priority => Prowler::Priority::NORMAL
      )

      Prowler.delayed = false
      Prowler.notify "Event Name", "Message Text", :delayed => true
    end

    should "send a custom url" do
      stub_request(:post, "#{Prowler::SERVICE_URL}/add")

      Prowler.notify "Event Name", "Message Text", :url => "http://www.pixeltrix.co.uk"

      assert_requested :post, "#{Prowler::SERVICE_URL}/add", :body => {
        :application => "Application Name",
        :apikey => "apikey",
        :event => "Event Name",
        :description => "Message Text",
        :priority => Prowler::Priority::NORMAL.to_s,
        :url => "http://www.pixeltrix.co.uk"
      }
    end

    should "send with a high priority using options" do
      stub_request(:post, "#{Prowler::SERVICE_URL}/add")

      Prowler.notify "Event Name", "Message Text", :priority => Prowler::Priority::HIGH

      assert_requested :post, "#{Prowler::SERVICE_URL}/add", :body => {
        :application => "Application Name",
        :apikey => "apikey",
        :event => "Event Name",
        :description => "Message Text",
        :priority => Prowler::Priority::HIGH.to_s
      }
    end

    should "send the provider key if configured" do
      stub_request(:post, "#{Prowler::SERVICE_URL}/add")

      Prowler.provider_key = "providerkey"
      Prowler.notify "Event Name", "Message Text"

      assert_requested :post, "#{Prowler::SERVICE_URL}/add", :body => {
        :application => "Application Name",
        :providerkey => "providerkey",
        :apikey => "apikey",
        :event => "Event Name",
        :description => "Message Text",
        :priority => Prowler::Priority::NORMAL.to_s
      }
    end

    should "allow passing the API key as a parameter" do
      stub_request(:post, "#{Prowler::SERVICE_URL}/add")

      Prowler.notify "Event Name", "Message Text", "apikey1"

      assert_requested :post, "#{Prowler::SERVICE_URL}/add", :body => {
        :application => "Application Name",
        :apikey => "apikey1",
        :event => "Event Name",
        :description => "Message Text",
        :priority => Prowler::Priority::NORMAL.to_s
      }
    end

    should "allow passing multiple API keys as a parameter" do
      stub_request(:post, "#{Prowler::SERVICE_URL}/add")

      Prowler.notify "Event Name", "Message Text", %w[apikey1 apikey2]

      assert_requested :post, "#{Prowler::SERVICE_URL}/add", :body => {
        :application => "Application Name",
        :apikey => "apikey1,apikey2",
        :event => "Event Name",
        :description => "Message Text",
        :priority => Prowler::Priority::NORMAL.to_s
      }
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
      stub_request :get, "#{Prowler::SERVICE_URL}/verify?apikey=apikey1"

      Prowler.api_key = %w(apikey1 apikey2)
      Prowler.verify

      assert_requested :get, "#{Prowler::SERVICE_URL}/verify?apikey=apikey1"
    end

    should "not send notifications if send_notifications is false" do
      stub_request :get, "#{Prowler::SERVICE_URL}/verify?apikey=apikey"

      Prowler.send_notifications = false
      Prowler.verify

      assert_not_requested :get, "#{Prowler::SERVICE_URL}/verify?apikey=apikey"
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
      stub_request :get, "#{Prowler::SERVICE_URL}/verify?apikey=apikey&providerkey=providerkey"

      Prowler.provider_key = "providerkey"
      Prowler.verify

      assert_requested :get, "#{Prowler::SERVICE_URL}/verify?apikey=apikey&providerkey=providerkey"
    end

    should "allow passing an API key as a parameter" do
      stub_request :get, "#{Prowler::SERVICE_URL}/verify?apikey=apikey1"
      Prowler.verify "apikey1"
      assert_requested :get, "#{Prowler::SERVICE_URL}/verify?apikey=apikey1"
    end

    should "only verify the first API key passed as a parameter" do
      stub_request :get, "#{Prowler::SERVICE_URL}/verify?apikey=apikey1"
      Prowler.verify %w[apikey1 apikey2]
      assert_requested :get, "#{Prowler::SERVICE_URL}/verify?apikey=apikey1"
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

      should "delay sending using parameter" do
        Prowler::Application.any_instance.expects(:enqueue_delayed_job).with(
          :application => "Application Name",
          :providerkey => nil,
          :apikey => "apikey",
          :event => "Event Name",
          :description => "Message Text",
          :priority => Prowler::Priority::NORMAL
        )

        Prowler.delayed = false
        Prowler.notify "Event Name", "Message Text", Prowler::Priority::NORMAL, true
      end

      should "send with a high priority using parameter" do
        stub_request(:post, "#{Prowler::SERVICE_URL}/add")

        Prowler.notify "Event Name", "Message Text", Prowler::Priority::HIGH

        assert_requested :post, "#{Prowler::SERVICE_URL}/add", :body => {
          :application => "Application Name",
          :apikey => "apikey",
          :event => "Event Name",
          :description => "Message Text",
          :priority => Prowler::Priority::HIGH.to_s
        }
      end
    end
  end
end
