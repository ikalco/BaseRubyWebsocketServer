require './websocket_server.rb'

wss = WebSocketServer.new(2345)

wss.on("connection") do |web_socket|
	puts "Connected to #{web_socket.ip}"

	web_socket.on("message_text") do |msg|
		puts msg
	end

	web_socket.on("message_binary") do |msg|
		puts msg
	end

	web_socket.on("close") do |reason|
		puts "Disconnected from #{web_socket.ip} for #{reason}"
	end
end

wss.start()
