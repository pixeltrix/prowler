require 'prowler'
require 'rails'

class Prowler
  class Railtie < Rails::Railtie
    rake_tasks do
      require "prowler/tasks"
    end
  end
end