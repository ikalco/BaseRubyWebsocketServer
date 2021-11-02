httpServer = TCPServer.new 5500

def sendFile (socket, filePath)
    if (filePath == "") then filePath = "index.html" end
    fileTypeBefore = filePath.split('.')[-1]
    if (fileTypeBefore == 'html')
        fileType = 'html'
    elsif (fileTypeBefore == 'css')
        fileType = 'css'
    elsif (fileTypeBefore == 'js')
        fileType = 'javascript'
    elsif (fileTypeBefore == 'mjs')
        #fileType = 'javascript'
    elsif (fileTypeBefore == "txt")
        #fileType = 'plain'
        return
    else
        #fileType = filePath.split('.')[-1];
        return
    end

    data = "HTTP/1.1 200 OK\r\n"
    data += "Content-Type: text/" + fileType + "; charset=utf-8\r\n"
    data += "\r\n"

    file = File.open(filePath)
    fileData = file.read
    file.close

    data += fileData + "\r\n\r\n"
    socket.write data
end

puts "Access http://localhost:5500"

# serving html
Thread.new {
    loop do

        httpClient = httpServer.accept
        # Read the HTTP request. We know it's finished when we see a line with nothing but \r\n
        httpRequest = ""
        while (line = httpClient.gets) && (line != "\r\n")
            httpRequest += line
        end

        pieces = httpRequest.split("\n")
        if pieces.length > 0
            STDERR.puts pieces[0]
            if pieces[0].include? "GET"
                if pieces[0].include? " /"
                    filePath = pieces[0].split(' ')[1][1..-1]
                    sendFile httpClient, filePath
                end
            end
        end
        httpClient.close
    end
}