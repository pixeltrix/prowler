require 'prowler'
require 'rails'

module Prowler
  class Railtie < Rails::Railtie
    rake_tasks do
      require "prowler/tasks"
    end
  end
end