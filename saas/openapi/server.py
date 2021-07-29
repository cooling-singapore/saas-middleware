import http.server
import socketserver

PORT = 8000

handler = http.server.SimpleHTTPRequestHandler


def run():
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print("Server started at localhost:" + str(PORT))
        httpd.serve_forever()


if __name__ == '__main__':
    run()
