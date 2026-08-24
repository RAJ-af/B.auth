bind_socket = "0.0.0.0:11332";
upstream "local" {
  default = yes;
  self_scan = yes;
}
