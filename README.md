Network Security Data Receiver

A lightweight client–server project that demonstrates secure data transmission from an embedded device to a backend service using HTTP and JSON.

This repository includes:

A Python Flask server that receives and logs incoming data

A microcontroller client (Arduino/ESP-based) that sends JSON payloads over the network

The project is designed for educational use in networking, IoT, and network security fundamentals.

Features

RESTful HTTP communication

JSON-based data transfer

Lightweight Flask backend

Compatible with Arduino / ESP8266 / ESP32

Simple and extensible architecture

Repository Structure
.
├── netsec.ino      # Embedded client (Arduino / ESP)
├── server.py       # Flask backend server
└── README.md

Backend Server

The backend server is implemented using Flask and exposes a single endpoint to receive data from clients.

Endpoint Details

Route: /data

Method: POST

Payload: JSON

Response: JSON status message

Incoming data is printed to the console for inspection and debugging.
The server listens on all interfaces at port 8080.

This behavior is defined in server.py 

server

.

Running the Server
Prerequisites

Python 3.8+

pip

Installation
pip install flask

Start the Server
python server.py


The server will be accessible at:

http://<server-ip>:8080/data

Embedded Client

The netsec.ino file contains the embedded client code responsible for:

Establishing a network connection

Creating JSON-formatted data

Sending data to the backend via HTTP POST

The client can be adapted to send:

Sensor data

System status information

Network or security-related metrics

Data Flow Overview

Embedded device generates or collects data

Data is serialized as JSON

HTTP POST request is sent to the server

Server logs the data and responds with a status message

Example response:

{
  "status": "ok"
}

Use Cases

IoT backend prototyping

Network security demonstrations

Client–server communication practice

Embedded systems coursework

Data ingestion testing

Security Notice

This project does not implement:

Authentication

Authorization

Encryption (HTTPS)

It is intended for local, educational, or controlled environments only.
Do not deploy this server to a public network without additional security measures.

Future Improvements

HTTPS support

Token-based authentication

Data persistence (database)

Input validation and logging

Rate limiting

License

This project is provided for educational purposes.
You may adapt and extend it as needed.