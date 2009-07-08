require 'test/unit'
require 'rubygems'
require 'mocha'
require 'shoulda'
require File.join(File.dirname(__FILE__), "..", "lib", "prowler")

class ProwlerTest < Test::Unit::TestCase
  context "Prowler configuration" do
    setup do
      Prowler.reset_configuration
      Prowler.send_notifications = false
    end

    should "be done with a block" do
      Prowler.configure do |config|
        config.host = "prowler"
        config.port = 666
        config.secure = false
        config.api_key = "apikey"
        config.application = "application"
      end

      assert_equal "prowler",     Prowler.host
      assert_equal 666,           Prowler.port
      assert_equal false,         Prowler.secure
      assert_equal "apikey",      Prowler.api_key
      assert_equal "application", Prowler.application
    end

    should "set a default host" do
      assert_equal "prowl.weks.net", Prowler.host
    end

    should "set a default port" do
      assert_equal 443, Prowler.port
    end

    should "default to secure" do
      assert_equal true, Prowler.secure
    end

    should "not set a default application" do
      assert_equal nil, Prowler.application
    end

    should "not set a default API key" do
      assert_equal nil, Prowler.api_key
    end

    should "raise an exception if not configured" do
      assert_raises RuntimeError do
        Prowler.notify("Event", "Description", Prowler::Priority::NORMAL)
      end
    end
  end

  context "Prowler deprecated configuration" do
    setup do
      Logger.any_instance.stubs(:warn)
      Prowler.reset_configuration
      Prowler.send_notifications = false
    end

    should "be done with a block" do
      Prowler.configure do |config|
        config.host = "prowler"
        config.port = 666
        config.secure = false
        config.application = "application"
        config.username = "username"
        config.password = "password"
      end

      assert_equal "username",    Prowler.username
      assert_equal "password",    Prowler.password
    end

    should "log a warning when using the deprecated API" do
      Logger.any_instance.expects(:warn).with("The username/password API has been deprecated please switch to using an API key.")
      Prowler.configure { |config| config.username = "username" }
    end

    should "not set a default username" do
      assert_equal nil, Prowler.username
    end

    should "not set a default password" do
      assert_equal nil, Prowler.password
    end

    should "raise an exception if not configured" do
      assert_raises RuntimeError do
        Prowler.notify("Event", "Description", Prowler::Priority::NORMAL)
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
      Prowler.send_notifications = false
    end

    should "encode the url parameters" do
      expectation = Prowler.expects(:path)
      expectation.with("apikey", 0, "Application%20Name", "Event%20Name", "Message%20Text")
      expectation.returns("/publicapi/add?apikey=apikey&priority=0application=Application%20Name&event=Event%20Name&description=Message%20Text")
      Prowler.notify("Event Name", "Message Text", Prowler::Priority::NORMAL)
    end

    should "not verify SSL certificates" do
      Net::HTTP.any_instance.expects(:use_ssl=).with(true)
      Net::HTTP.any_instance.expects(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
      Prowler.notify("Event Name", "Message Text", Prowler::Priority::NORMAL)
    end

    should "not send notifications if send_notifications is false" do
      Net::HTTP.any_instance.expects(:request).never
      Prowler.notify("Event Name", "Message Text", Prowler::Priority::NORMAL)
    end
  end
end
