import socketserver
import http.server
import urllib.request
import time
import os
from dotenv import load_dotenv
from logConf import logger
from Security.DnsCheck import is_allowed_target
from Security.CheckJwtToken import checkJwt
from CacheStoring import CACHE, CACHE_TTL
from datetime import datetime, timedelta


load_dotenv()
PORT = int(os.getenv("PORT"))
MAX_RETRIES=int(os.getenv("MAX_RETRIES"))
RETRY_DELAY=int(os.getenv("RETRY_DELAY"))

#http.server is not recommendent for production, no security checks implemented
#SimpleHTTPRequestHandler inherits from .BaseHTTPRequestHandler
class SimpleProxy(http.server.SimpleHTTPRequestHandler):
    #This method overrides the base class’ do_GET. It will be called whenever the server receives an HTTP GET request for this handler.
    def fetch_res(self, target_url, method="GET", data=None):
        
        if method == "GET" and target_url in CACHE:
             cached_element = CACHE["target_url"]
             if datetime.now < cached_element["expDate"]:
                  logger.info(f"Cache hit for {target_url}")
                  return cached_element["content"], cached_element["headers"], cached_element["status"]
             else:
                  del CACHE[target_url]  # Expired entry
        for attempt  in range(1, MAX_RETRIES +1):
                try:
                    #urlopen =>opens target url,the with context ensures the response is closed automatically at the end of the block,
                    # returns an object HTTPResponse.
                    #Request handles the specific method, and atteches heads more easily
                    req = urllib.request.Request(target_url, data=data, method=method)
                    for k,v in self.headers.items(): 
                        # contains hop-by-hop headers — meaning they’re only valid for a single transport “hop” 
                        # between two nodes (client ↔ proxy or proxy ↔ server), not end-to-end
                        if k.lower() not in ("transfer-encoding", "connection", "content-encoding", "content-length"): # Exclude hop-by-hop headers
                            req.add_header(k,v)
                    with urllib.request.urlopen(req, timeout=10) as response:
                        content = response.read()
                        headers = response.headers
                        status= response.getcode()
                        # Cachio successful GET resp
                        if method == "GET" and status == 200:
                           CACHE[target_url]= {
                                "content": content,
                                "headers": headers,
                                "status": status,
                                #calcutation exping from now to 1 min
                                "expires": datetime.now() + timedelta(seconds=CACHE_TTL)
                           }
                        return content, headers, status
                except Exception as e:
                    if attempt < MAX_RETRIES:
                        logger.warning(f"Call went into catch {target_url}!!")
                        time.sleep(RETRY_DELAY)
                    else:
                        logger.error(f"${str(e)} ALL {MAX_RETRIES} attemps failed")
                        return b"Server error after retries", {}, 502
                    
    def respond_to_client(self,status, headers, content):
        self.send_response(status)
        for k, v in headers.items():
                 if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                     self.send_header(k, v)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)         

    def do_GET(self):
        #self.path equals "/https://example.com, remove 1st char
        target_url=self.path[1:]
        if not is_allowed_target(target_url=target_url):
            logger.fatal(f"not allowed url : {target_url}")
            self.send_response(400)
            self.end_headers()
            #wfile is a method of of BaseHTTPRequestHandler, it contains the output stream for writing a response back to the client. 
            self.wfile.write(b"Invalid URL")
            return
        
        content, headers, status = self.fetch_res(target_url, method="GET")
        self.respond_to_client(status, headers, content)
        logger.info(target_url)
        
            
    def do_POST(self):
        target_url=self.path[1:]
        if not (is_allowed_target(target_url=target_url)):
            logger.fatal(f"not allowed url : {target_url}")
            self.send_response(400)
            #Send the blank line ending the MIME headers.
            self.end_headers()
            self.wfile.write(b"Invalid URL")
            return
        
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length>0 else None
        content, headers, status = self.fetch_res(target_url, method="POST", data=post_data)
        self.respond_to_client(status, headers, content)
        


# enters the server main loop, accepting connections and handling requests until the process is terminated.
#TCPServer is single trhad, one req at a time, proxy becomes unresponsive under multiple clients
#ThreadingTCPServer enable concurrent request handling
if __name__ == "__main__":
     with socketserver.ThreadingTCPServer(("",PORT), SimpleProxy) as http:
         print(f"Proxy running on port {PORT}")
         http.serve_forever()