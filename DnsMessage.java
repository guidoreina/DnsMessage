import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.util.Vector;
import java.net.InetAddress;
import java.net.UnknownHostException;

class DnsMessage {
  // Maximum length of a DNS message.
  private final static int MAX_LEN = 512;

  // Length of the DNS header.
  private final static int HEADER_LEN = 12;

  // Maximum number of DNS pointers.
  private final static int MAX_POINTERS = 64;

  // Maximum length of a domain name.
  private final static int DOMAIN_NAME_MAX_LEN = 255;

  // Buffer containing the DNS message.
  private byte[] buffer = null;

  // Length of the DNS message.
  private int length = 0;

  // Offset in the buffer.
  private int offset = 0;

  // Domain.
  public String domain = null;

  // IP addresses.
  public Vector<String> ipAddresses = new Vector<String>();

  // Constructor.
  DnsMessage() {
  }

  // Read file.
  public byte[] read(String filename) {
    File file = new File(filename);

    // If the file exists...
    if (file.isFile()) {
      // Get file size.
      long filesize = file.length();

      // If the file is not too big...
      if (filesize <= MAX_LEN) {
        try {
          // Open file for reading.
          BufferedInputStream
            reader = new BufferedInputStream(new FileInputStream(filename));

          // Create buffer.
          byte[] buf = new byte[(int) filesize];

          // Read DNS message.
          int read = reader.read(buf, 0, (int) filesize);

          // If all the bytes could be read...
          if (read == filesize) {
            return buf;
          } else {
            System.err.printf("Error reading from '%s'.\n", filename);
          }
        } catch (IOException e) {
          System.err.printf("Error reading from '%s'.\n", filename);
        }
      } else {
        System.err.printf("File '%s' is too big (%d bytes).\n",
                          filename,
                          filesize);
      }
    } else {
      System.err.printf("File '%s' doesn't exist.\n", filename);
    }

    return null;
  }

  private int ntohs(byte[] buf, int off) {
    return ((buf[off] & 0xff) << 8) | (buf[off + 1] & 0xff);
  }

  private void arrayCopy(byte[] src,
                         int srcPos,
                         byte[] dest,
                         int destPos,
                         int length) {
    for (int i = 0; i < length; i++) {
      dest[destPos + i] = src[srcPos + i];
    }
  }

  public void clear() {
    domain = null;
    ipAddresses.clear();
  }

  public boolean parse(byte[] buf) {
    clear();

    // Save reference to the buffer.
    buffer = buf;

    // Save message length.
    length = buffer.length;

    // If the DNS message should be processed...
    if ((length >= HEADER_LEN)           && // The message is not too short.
        (length <= MAX_LEN)              && // The message is not too long.
        (((buffer[2] >> 3) & 0x0f) <= 2) && // 0 <= OPCODE <= 2
        ((buffer[2] & 0x02) == 0)        && // The message was not truncated.
        ((buffer[3] & 0x0f) == 0)) {        // RCODE = 0
      int qdcount = ntohs(buffer, 4);

      // If there are questions...
      if (qdcount > 0) {
        offset = HEADER_LEN;

        // If the QNAME is valid and the QTYPE and QCLASS fit...
        if (((domain = parse_domain_name()) != null) &&
            (offset + 4 <= length)) {
          // If the QCLASS is 1 (IN [Internet])...
          if (ntohs(buffer, offset + 2) == 1) {
            // Get QTYPE.
            int qtype = ntohs(buffer, offset);

            if (qtype <= 255) {
              // Query?
              if ((buffer[2] & 0x80) == 0) {
                return true;
              } else {
                int ancount = ntohs(buffer, 6);

                // If there are answers...
                if (ancount > 0) {
                  // Skip QTYPE and QCLASS.
                  offset += 4;

                  // Skip following questions (if any).
                  for (int i = 2; i <= qdcount; i++) {
                    if (!skip_question()) {
                      return false;
                    }
                  }

                  // Process answers.
                  for (int i = 1; i <= ancount; i++) {
                    if ((skip_domain_name()) && (offset + 10 <= length)) {
                      int rdlength = ntohs(buffer, offset + 8);

                      int next;
                      if ((next = offset + 10 + rdlength) <= length) {
                        // If the CLASS is 1 (IN [Internet])...
                        if (ntohs(buffer, offset + 2) == 1) {
                          // Check type.
                          switch (ntohs(buffer, offset)) {
                            case 1: // A (host address [IPv4]).
                              if (rdlength == 4) {
                                byte[] b = new byte[4];
                                arrayCopy(buffer, offset + 10, b, 0, 4);

                                try {
                                  InetAddress
                                    addr = InetAddress.getByAddress(b);

                                  ipAddresses.add(addr.getHostAddress());
                                } catch (UnknownHostException e) {
                                }
                              } else {
                                return false;
                              }

                              break;
                            case 28: // AAAA (IPv6).
                              if (rdlength == 16) {
                                byte[] b = new byte[16];
                                arrayCopy(buffer, offset + 10, b, 0, 16);

                                try {
                                  InetAddress
                                    addr = InetAddress.getByAddress(b);

                                  ipAddresses.add(addr.getHostAddress());
                                } catch (UnknownHostException e) {
                                }
                              } else {
                                return false;
                              }

                              break;
                          }
                        }

                        offset = next;
                      } else {
                        return false;
                      }
                    } else {
                      return false;
                    }
                  }

                  return !ipAddresses.isEmpty();
                }
              }
            }
          }
        }
      }
    }

    return false;
  }

  private String parse_domain_name()
  {
    byte[] domain = new byte[DOMAIN_NAME_MAX_LEN];
    int len = 0;
    int npointers = 0;

    // Work with a copy of the offset.
    int off = offset;

    while (off < length) {
      switch (buffer[off] & 0xc0) {
        case 0: // Label.
          // If not the null label...
          if (buffer[off] > 0) {
            int next;
            if (((next = off + 1 + buffer[off]) < length) &&
                (len + 1 + buffer[off] <= DOMAIN_NAME_MAX_LEN)) {
              // If not the first label...
              if (len > 0) {
                domain[len++] = '.';
              }

              // Copy label.
              arrayCopy(buffer, off + 1, domain, len, buffer[off]);

              len += buffer[off];

              off = next;
            } else {
              return null;
            }
          } else {
            // Null label.

            // If not the root domain name...
            if (len > 0) {
              if (npointers == 0) {
                offset = off + 1;
              }

              return new String(domain, 0, len);
            } else {
              return null;
            }
          }

          break;
        case 0xc0: // Pointer.
          if ((++npointers <= MAX_POINTERS) && (off + 1 < length)) {
            // Compute pointer offset.
            int ptroff = ntohs(buffer, off) & 0x3fff;

            // Valid offset?
            if ((ptroff >= HEADER_LEN) && (ptroff < length)) {
              // First pointer?
              if (npointers == 1) {
                offset = off + 2;
              }

              off = ptroff;
            } else {
              return null;
            }
          } else {
            return null;
          }

          break;
        default:
          return null;
      }
    }

    return null;
  }

  private boolean skip_domain_name()
  {
    int len = 0;
    int npointers = 0;

    // Work with a copy of the offset.
    int off = offset;

    while (off < length) {
      switch (buffer[off] & 0xc0) {
        case 0: // Label.
          // If not the null label...
          if (buffer[off] > 0) {
            int next;
            if (((next = off + 1 + buffer[off]) < length) &&
                (len + 1 + buffer[off] <= DOMAIN_NAME_MAX_LEN)) {
              // If not the first label...
              if (len > 0) {
                len += (1 + buffer[off]);
              } else {
                len += buffer[off];
              }

              off = next;
            } else {
              return false;
            }
          } else {
            // Null label.

            if (npointers == 0) {
              offset = off + 1;
            }

            return true;
          }

          break;
        case 0xc0: // Pointer.
          if ((++npointers <= MAX_POINTERS) && (off + 1 < length)) {
            // Compute pointer offset.
            int ptroff = ntohs(buffer, off) & 0x3fff;

            // Valid offset?
            if ((ptroff >= HEADER_LEN) && (ptroff < length)) {
              // First pointer?
              if (npointers == 1) {
                offset = off + 2;
              }

              off = ptroff;
            } else {
              return false;
            }
          } else {
            return false;
          }

          break;
        default:
          return false;
      }
    }

    return false;
  }

  private boolean skip_question()
  {
    if ((skip_domain_name()) && (offset + 4 <= buffer.length)) {
      offset += 4;

      return true;
    } else {
      return false;
    }
  }

  public static void main(String[] args) {
    if (args.length == 1) {
      DnsMessage dnsmsg = new DnsMessage();

      // Read file.
      byte[] buf = dnsmsg.read(args[0]);

      // If the file could be read...
      if (buf != null) {
        // Parse DNS message.
        if (dnsmsg.parse(buf)) {
          System.out.printf("%s:\n", dnsmsg.domain);

          // For each IP address...
          for (String ipAddress : dnsmsg.ipAddresses) {
            System.out.printf("  %s\n", ipAddress);
          }
        } else {
          System.err.println("Error parsing DNS message.");
        }
      }
    } else {
      System.err.println("Usage: DnsMessage <filename>");
    }
  }
}
