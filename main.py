import socketserver
import http.server
import urllib.request
from logConf import logger
from Security.DnsCheck import is_allowed_target
from Security.CheckJwtToken import checkJwt

PORT = 8080
#http.server is not recommendent for production, no security checks implemented
#SimpleHTTPRequestHandler inherits from .BaseHTTPRequestHandler
class SimpleProxy(http.server.SimpleHTTPRequestHandler):
    #This method overrides the base class’ do_GET. It will be called whenever the server receives an HTTP GET request for this handler.
    def do_GET(self):
        #self.path equals "/https://example.com, remove 1st char
        target_url=self.path[1:]
        if not is_allowed_target(target_url=target_url):
            logger.fatal(f"not allowed url : {target_url}")
            self.send_response(400)
            self.end_headers()
            #wfile is a method of of BaseHTTPRequestHandler, it contains the output stream for writing a response back to the client. 
            self.wfile.write(b"Invalid URL")
        else:
            logger.info(target_url)
            checkJwt(self)
            try:
                #opens target url,the with context ensures the response is closed automatically at the end of the block,
                # returns an object HTTPResponse.
                with urllib.request.urlopen(target_url, timeout=10) as response:
                     content = response.read()
                     content_length = len(content) 
                     logger.info(f"pipppi ||| {response.reason}")
                     logger.info(content)
                     self.send_response(response.getcode())
                     for k,v in response.headers.items(): 
                         if k.lower() not in ("transfer-encoding", "connection", "content-encoding", "content-length"): # Exclude hop-by-hop headers
                             self.send_header(k, v)
                     # Explicitly setting Content-Length prevents the '_headers_buffer' error
                     # by giving the base class the necessary information to finalize the response.
                     self.send_header("Content-Length", str(content_length))
                     #end of the response headers to the client, can be followed by send_header(name, value) calls 
                     # to add headers (like Content-Type or Content-Length), but none are set here. 
                     # Because no Content-Type header is sent, the client will have to guess the content type or 
                     # treat it as application/octet-stream.
                     self.end_headers()
                      #Writes the bytes content to the client’s socket output stream
                     self.wfile.write(content)
            except Exception as e:
                logger.error(e)
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())

# enters the server main loop, accepting connections and handling requests until the process is terminated.
#TCPServer is single trhad, one req at a time, proxy becomes unresponsive under multiple clients
#ThreadingTCPServer enable concurrent request handling
with socketserver.ThreadingTCPServer(("",PORT), SimpleProxy) as httpd:
    print(f"Proxy running on port {PORT}")
    httpd.serve_forever()