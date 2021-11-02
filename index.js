// connect to server
let socket;
let connected = false;

socket = new WebSocket("ws://" + window.location.hostname + ":2345");

socket.onopen = function (event) {
  connected = true;
};

socket.onmessage = function (event) {
  console.log(event.data);
};

socket.onclose = function (event) {
  console.log("You have been disconnected from the websocket server!");
};
