namespace :prowler do
  desc "Verify your Prowler installation by sending a test notification to the Prowl iPhone application"
  task :test => :environment do
    Prowler.notify "Test Message", "Testing, testing, testing ..."
  end
end
