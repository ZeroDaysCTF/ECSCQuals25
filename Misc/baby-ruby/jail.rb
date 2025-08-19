#!/usr/bin/env ruby

require 'socket'

BLACKLIST = /[\/]|flag.txt/

class JailContext
  instance_methods.each do |m|
    undef_method m unless m.to_s =~ /^__|^object_id$/
  end

  def get_binding
    binding
  end
end

server = TCPServer.new('0.0.0.0', 2337)
puts "Ruby jail listening on port 2337..."

loop do
  client = server.accept
  puts "Connection from #{client.peeraddr}"

  begin
    jail = JailContext.new
    jail_binding = jail.get_binding

    client.puts "Welcome to Ruby Jail. Input your code."

    loop do
      client.print ">>> "
      inp = client.gets
      break unless inp

      inp.chomp!

      unless inp.ascii_only?
        client.puts "Not ASCII"
        next
      end

      if inp =~ BLACKLIST
        client.puts "Blocked"
        next
      end

      begin
        result = eval(inp, jail_binding, __FILE__, __LINE__)
        client.puts "=> #{result.inspect}" unless result.nil?
      rescue Exception => e
        client.puts "Error: #{e.class} - #{e.message}"
      end
    end
  rescue => e
    puts "Error: #{e}"
  ensure
    client.close
  end
end
