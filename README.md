
# TI BLE Legacy NPI (SPI)

Protocol analyzer extension for [Saleae Logic 2][1] for decoding TI Bluetooth
data using the [Legacy NPI][2] interface and [TI Vendor Specific][3] commands.

[1]: https://www.saleae.com/downloads
[2]: https://software-dl.ti.com/simplelink/esd/simplelink_cc13x2_26x2_sdk/3.30.00.03/exports/docs/ble5stack/ble_user_guide/html/ble-stack-common/npi-index.html
[3]: https://software-dl.ti.com/simplelink/esd/simplelink_cc13x2_sdk/1.60.00.29_new/exports/docs/ble5stack/vendor_specific_guide/BLE_Vendor_Specific_HCI_Guide/hci_interface.html

## Getting started

* Capture SPI transactions and add a SPI analyzer.
  * Use nSRDY or nMRDY as CS if there isn't a separate CS line.
* Add two copies of the analyses from this extension.
  * In both, select the SPI analyzer.
  * In one, select "tx" and in the other select "rx"
