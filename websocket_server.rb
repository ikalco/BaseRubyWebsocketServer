require 'socket' # Provides TCPServer and TCPSocket classes
require 'digest/sha1'
require './http_server.rb'

def sendMessage (socket, msg)
  #STDERR.puts "Sending message : #{ msg.inspect }"

  output = [0b10000001, msg.size, msg]

  socket.write output.pack("CCA#{ msg.size }")
end

def recvMessage (socket)
  first_byte = socket.getbyte

  if first_byte == nil then return end
  fin = first_byte & 0b10000000
  opcode = first_byte & 0b00001111

  if (opcode == 8) then return socket.close() end

  #STDERR.puts "First Byte: 0b#{ first_byte.inspect }"
  #STDERR.puts "Fin: 0b#{ fin.to_s(2) }"
  #STDERR.puts "Opcode: #{ opcode }"

  #raise "We don't support continuations" unless fin
  if (opcode == 1)
    #raise "We only support opcode 1 and 8" unless opcode == 1 || opcode == 8

    second_byte = socket.getbyte
    is_masked = second_byte & 0b10000000
    payload_size = second_byte & 0b01111111

    #puts payload_size

    #raise "All incoming frames should be masked according to the websocket spec" unless is_masked
    raise "We only support payloads < 126 bytes in length" unless payload_size < 126

    #STDERR.puts "Payload size: #{ payload_size } bytes"

    mask = 4.times.map { socket.getbyte }
    #STDERR.puts "Got mask: #{ mask.inspect }"

    data = payload_size.times.map { socket.getbyte }
    #STDERR.puts "Got masked data: #{ data.inspect }"

    unmasked_data = data.each_with_index.map { |byte, i| byte ^ mask[i % 4] }
    #STDERR.puts "Unmasked the data: #{ unmasked_data.inspect }"

    plainMsg = unmasked_data.pack('C*').force_encoding('utf-8')

    #STDERR.puts "Recieve Message: #{ plainMsg.inspect }"

    return plainMsg
    #raise "We only support opcode 1 and 8"
  end
end

def websocketHandshake (socket)
  # Read the HTTP request. We know it's finished when we see a line with nothing but \r\n
  http_request = ""
  while (line = socket.gets) && (line != "\r\n")
    http_request += line
  end


  # Grab the security key from the headers. If one isn't present, close the connection.
  if matches = http_request.match(/^Sec-WebSocket-Key: (\S+)/)
    websocket_key = matches[1]
    STDERR.puts "Websocket handshake detected with key: #{ websocket_key }"
  else
    STDERR.puts "Aborting non-websocket connection"
    socket.close
    return
  end


  response_key = Digest::SHA1.base64digest([websocket_key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"].join)
  #STDERR.puts "Responding to handshake with key: #{ response_key }"

  socket.write <<-eos
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: #{ response_key }

  eos

  STDERR.puts "Handshake completed."
end

webSocketServer = TCPServer.new 2345

loop do

  # websocket loop  
  Thread.start(webSocketServer.accept) do |socket|

    websocketHandshake socket

    sendMessage(socket, "Hello World!")

    while (true)
      msg = recvMessage socket
    end

    socket.close()
  end
end

webSocketServer.close