#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define ATT_CID 4

void print_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <BD_ADDR>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Convert the Bluetooth address from a string to a bdaddr_t
    bdaddr_t bdaddr;
    if (str2ba(argv[1], &bdaddr) < 0) {
        print_error("Invalid Bluetooth address");
    }

    // Open a Bluetooth socket
    int dev_id = hci_get_route(NULL);
    int sock = hci_open_dev(dev_id);
    if (sock < 0) {
        print_error("Failed to open HCI socket");
    }

    // Set up the BLE connection parameters
    struct hci_request req;
    le_set_advertising_parameters_cp adv_params_cp;
    memset(&adv_params_cp, 0, sizeof(adv_params_cp));
    hci_le_set_advertising_parameters(&adv_params_cp, dev_id);
    memset(&req, 0, sizeof(req));
    req.ogf = OGF_LE_CTL;
    req.ocf = OCF_LE_SET_ADVERTISING_PARAMETERS;
    req.cparam = &adv_params_cp;
    req.clen = LE_SET_ADVERTISING_PARAMETERS_CP_SIZE;
    req.rparam = NULL;
    req.rlen = 0;

    if (hci_send_req(sock, &req, 1000) < 0) {
        print_error("Failed to set advertising parameters");
    }

    // Set up the BLE scan parameters
    le_set_scan_parameters_cp scan_params_cp;
    memset(&scan_params_cp, 0, sizeof(scan_params_cp));
    scan_params_cp.type = 0x01;  // Passive scanning
    scan_params_cp.interval = htobs(0x0010);
    scan_params_cp.window = htobs(0x0010);
    scan_params_cp.own_bdaddr_type = 0x00;  // Public device address
    scan_params_cp.filter = 0x00;  // Accept all advertising packets
    memset(&req, 0, sizeof(req));
    req.ogf = OGF_LE_CTL;
    req.ocf = OCF_LE_SET_SCAN_PARAMETERS;
    req.cparam = &scan_params_cp;
    req.clen = LE_SET_SCAN_PARAMETERS_CP_SIZE;
    req.rparam = NULL;
    req.rlen = 0;

    if (hci_send_req(sock, &req, 1000) < 0) {
        print_error("Failed to set scan parameters");
    }

    // Enable BLE scanning
    le_set_scan_enable_cp scan_enable_cp;
    memset(&scan_enable_cp, 0, sizeof(scan_enable_cp));
    scan_enable_cp.enable = 0x01;  // Enable scanning
    scan_enable_cp.filter_dup = 0x00;  // Disable duplicate filtering
    memset(&req, 0, sizeof(req));
    req.ogf = OGF_LE_CTL;
    req.ocf = OCF_LE_SET_SCAN_ENABLE;
    req.cparam = &scan_enable_cp;
    req.clen = LE_SET_SCAN_ENABLE_CP_SIZE;
    req.rparam = NULL;
    req.rlen = 0;

    if (hci_send_req(sock, &req, 1000) < 0) {
        print_error("Failed to enable scanning");
    }

    // Set BLE event filter to receive only LE Meta Events
    struct hci_filter nf, of;
    socklen_t olen;

    if (getsockopt(sock, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
        print_error("Could not get socket options");
    }

    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
    hci_filter_set_event(EVT_LE_META_EVENT, &nf);

    if (setsockopt(sock, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
        print_error("Could not set socket options");
    }

    // Listen for BLE events
    while (1) {
        unsigned char buf[HCI_MAX_EVENT_SIZE];
        ssize_t len = read(sock, buf, sizeof(buf));
        if (len < 0) {
            print_error("Failed to read from HCI socket");
        }

        evt_le_meta_event *meta = (evt_le_meta_event *)(buf + (1 + HCI_EVENT_HDR_SIZE));
        len -= (1 + HCI_EVENT_HDR_SIZE);

        if (meta->subevent != EVT_LE_ADVERTISING_REPORT) {
            continue;
        }

        le_advertising_info *info = (le_advertising_info *)(meta->data + 1);
        int8_t rssi = *(meta->data + meta->length);

        // Check if the received packet is from the desired device
        if (memcmp(&info->bdaddr, &bdaddr, sizeof(bdaddr_t)) == 0) {
            // Assuming the accelerometer data is in the manufacturer-specific data
            int data_length = info->length - 7;  // Subtracting the header and address length
            unsigned char *data = info->data + 7;  // Skip header and address

            // Your logic for processing accelerometer data goes here
            // Example: print the received data
            printf("Received Accelerometer Data: ");
            for (int i = 0; i < data_length; i++) {
                printf("%02X ", data[i]);
            }
            printf("\n");

            // Your logic for detecting motion or stationary state goes here
            // Example: simple motion detection based on RSSI
            if (rssi > -70) {
                printf("Motion detected: Tag is moving\n");
            } else {
                printf("No motion detected: Tag is stationary\n");
            }
        }
    }

    // Disable BLE scanning
    memset(&req, 0, sizeof(req));
    req.ogf = OGF_LE_CTL;
    req.ocf = OCF_LE_SET_SCAN_ENABLE;
    req.cparam = &scan_enable_cp;
    req.clen = LE_SET_SCAN_ENABLE_CP_SIZE;
    req.rparam = NULL;
    req.rlen = 0;
    scan_enable_cp.enable = 0x00;  // Disable scanning

    if (hci_send_req(sock, &req, 1000) < 0) {
        print_error("Failed to disable scanning");
    }

    // Close the Bluetooth socket
    close(sock);

    return 0;
}
