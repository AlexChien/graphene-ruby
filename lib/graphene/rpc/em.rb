#!/usr/bin/env ruby
# require 'rubygems'
require 'eventmachine'

module MyKeyboardHandler
  def receive_data keystrokes
    puts "I received the following data from the keyboard: #{keystrokes}"
  end
end

EM.run {
  EM.open_keyboard(MyKeyboardHandler)
}