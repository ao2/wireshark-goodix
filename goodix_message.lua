protocol = Proto("goodix",  "Goodix Fingerprint Sensor Message Protocol")

cmd0_field = ProtoField.uint8("goodix.cmd0", "cmd0", base.HEX, nil, 0xF0)
cmd1_field = ProtoField.uint8("goodix.cmd1", "cmd1", base.HEX, nil, 0x0E)
cmd_continuation = ProtoField.bool("goodix.cmd_continuation", "Continuation flag", 8, nil, 0x01)
len = ProtoField.uint16("goodix.len", "Length", base.DEC)
cksum = ProtoField.uint8("goodix.cksum", "Checksum", base.HEX)

body = ProtoField.none("goodix.body", "body")

ack_bool = ProtoField.bool("goodix.ack_bool", "Unknown bool", 2, nil, 0x02)
ack_true = ProtoField.bool("goodix.ack_true", "Always true", 2, nil, 0x01)
ack_cmd = ProtoField.uint8("goodix.ack_cmd", "ACKed Command", base.HEX)
firmware_version = ProtoField.stringz("goodix.firmware_version", "Firmware Version")
enabled = ProtoField.bool("goodix.enabled", "Enabled")

mcu_state_image = ProtoField.bool("goodix.mcu_state.is_image_valid", "isImageValid", 8, nil, 0x01) -- Meaning unknown
mcu_state_tls = ProtoField.bool("goodix.mcu_state.is_tls_connected", "isTlsConnected", 8, nil, 0x02)
mcu_state_spi = ProtoField.bool("goodix.mcu_state.is_spi_send", "isSpiSend", 8, nil, 0x04) -- Meaning unknown
mcu_state_locked = ProtoField.bool("goodix.mcu_state.is_locked", "isLocked", 8, nil, 0x08) -- Meaning unknown
mcu_state_sensor_crc32_valid = ProtoField.bool("goodix.mcu_state.sensor_crc32_valid", "Correct crc32 on the last image from the sensor")

reset_flag_sensor = ProtoField.bool("goodix.reset_flag.sensor", "Reset Sensor", 8, nil, 0x01)
reset_flag_mcu = ProtoField.bool("goodix.reset_flag.mcu", "Soft Reset MCU", 8, nil, 0x02)
reset_flag_sensor_copy = ProtoField.bool("goodix.reset_flag.sensor_copy", "Reset Sensor (copy)", 8, nil, 0x04) -- Driver always sets this at the same time as reset_flag.sensor, firmware ignores this one

sensor_reset_success = ProtoField.bool("goodix.sensor_reset_success", "Sensor reset success") -- False if a timeout occurs getting a response from the sensor
sensor_reset_number = ProtoField.uint16("goodix.sensor_reset_number", "Sensor reset number") -- Contents unknown, but it's a LE short sent if the sensor reset succeeds

reg_multiple = ProtoField.bool("goodix.reg.multiple", "Multiple addresses") -- Only false is used by driver, no dissection implemented for true
reg_address = ProtoField.uint16("goodix.reg.addr", "Base Address", base.HEX)
reg_len = ProtoField.uint8("goodix.reg.len", "Length")

pwrdown_scan_freq = ProtoField.uint16("goodix.powerdown_scan_frequency", "Powerdown Scan Frequency")

config_sensor_chip = ProtoField.uint8("goodix.config_sensor_chip", "Sensor Chip", base.RANGE_STRING, {
                                         {0, 0, "GF3208"},
                                         {1, 1, "GF3288"},
                                         {2, 2, "GF3266"},
}, 0xF0)

protocol.fields = {
   cmd0_field, cmd1_field, cmd_continuation, len, cksum, body,
   ack_cmd, ack_true, ack_bool,
   firmware_version,
   enabled,
   mcu_state_image, mcu_state_tls, mcu_state_spi, mcu_state_locked, mcu_state_sensor_crc32_valid,
   reset_flag_sensor, reset_flag_mcu, reset_flag_sensor_copy,
   sensor_reset_success, sensor_reset_number,
   reg_multiple, reg_address, reg_len,
   pwrdown_scan_freq,
   config_sensor_chip
}

function extract_cmd0_cmd1(cmd)
   return bit.rshift(cmd, 4), bit.rshift(cmd%16, 1)
end

function get_cmd_name(cmd)
   cmd0, cmd1 = extract_cmd0_cmd1(cmd)

   if commands[cmd0][cmd1] ~= nil then
      return commands[cmd0][cmd1].name
   else
      return string.format("%s.%x", commands[cmd0].category_name, cmd1)
   end
end

-- Nested table, keyed by [cmd0][cmd1]. 
commands = {
   [0x0] = {
      category_name = "NOP",
      [0x0] = {
         name = "nop",
         dissect_command = function(tree, buf)
            -- This packet has a fixed, non-standard checksum of 0x88
            -- Its purpose is unknown -- REd firmware does nothing when it receives one.
         end,
      }
   },
   [0x2] = {
      category_name = "Ima",
   },
   [0x3] = {
      category_name = "FDT",
   },
   [0x4] = {
      category_name = "FF",
   },
   [0x5] = {
      category_name = "NAV",
   },
   [0x6] = {
      category_name = "Sle",
   },
   [0x7] = {
      category_name = "IDL",
   },
   [0x8] = {
      category_name = "REG",
      [1] = {
         name = "Read Sensor Register",
         dissect_command = function(tree, buf)
            tree:add_le(reg_multiple, buf(0, 1))
            tree:add_le(reg_address, buf(1, 2))
            tree:add_le(reg_len, buf(3, 1)):append_text(" bytes")
         end,
         dissect_reply = function(tree, buf)
            -- Reply is just the bytes requested
         end,
      },
   },
   [0x9] = {
      category_name = "CHIP",
      -- Operations on the sensor chip (not the MCU)

      [0] = {
         name = "Upload Config",
         dissect_command = function(tree, buf)
            tree:add_le(config_sensor_chip, buf(0, 1))
         end,
         dissect_reply = function(tree, buf)
         end,
      },
      [2] = {
         name = "Set Powerdown Scan Frequency",
         dissect_command = function(tree, buf)
            -- I believe this is for a feature (POV/persistence of vision) where the sensor continues scanning while the laptop is asleep, and sends it to the laptop once it wakes up
            tree:add_le(pwrdown_scan_freq, buf(0, 2)) -- Units unknown, though mine is 100, so ms would make sense?
         end,
         dissect_reply = function(tree, buf)
            -- TODO check
         end,
      },
      [3] = {
         name = "Enable Chip",
         dissect_command = function(tree, buf)
            tree:add_le(enabled, buf(0, 1))
         end,
      },
   },
   [0xA] = {
      category_name = "OTHER",

      [1] = {
         name = "Reset",
         dissect_command = function(tree, buf)
            tree:add_le(reset_flag_sensor, buf(0, 1))
            tree:add_le(reset_flag_mcu, buf(0, 1))
            tree:add_le(reset_flag_sensor_copy, buf(0, 1))
         end,
         dissect_reply = function(tree, buf)
            tree:add_le(sensor_reset_success, buf(0, 1))
            tree:add_le(sensor_reset_number, buf(1, 2))
         end,
      },
      [3] = {
         name = "Read OTP",
         -- I believe OTP refers to one-time-programmable memory, which is written with calibration values at the factory
         dissect_command = function(tree, buf)
            -- Request is empty
         end,
         dissect_reply = function(tree, buf)
            -- The OTP (32 bytes for my sensor model, I believe it differs with others)
         end,

      },
      [4] = {
         name = "Firmware Version",
         dissect_command = function(tree, buf)
         end,
         dissect_reply = function(tree, buf)
            tree:add_le(firmware_version, buf())
         end,
      },
      [7] = {
         name = "Query MCU State",
         dissect_command = function(tree, buf)
            -- TODO what's the 0x55
         end,
         dissect_reply = function(tree, buf)
            tree:add_le(mcu_state_image, buf(0, 1))
            tree:add_le(mcu_state_tls, buf(0, 1))
            tree:add_le(mcu_state_spi, buf(0, 1))
            tree:add_le(mcu_state_locked, buf(0, 1))
            tree:add_le(mcu_state_sensor_crc32_valid, buf(3, 1))
         end,
      },
   },
   [0xB] = {
      category_name = "MSG",

      [0] = {
         name = "Ack",
         dissect_reply = function(tree, buf)
            tree:add_le(ack_true, buf(1, 1))
            tree:add_le(ack_bool, buf(1, 1)) -- commands 0-5 (inclusive) are ignored if this is true.
            tree:add_le(ack_cmd, buf(0, 1)):append_text(" (" .. get_cmd_name(buf(0,1):le_uint()) .. ")")
         end,
      },
   },
   [0xC] = {
      category_name = "NOTI",
   },
   [0xD] = {
      category_name = "TLSCONN",

      [0] = {
         name = "Request TLS Connection",
         dissect_command = function(tree, buf)
            -- No args.
            -- MCU doesn't do a normal reply (except the ack), but it triggers it to send a TLS Client Hello as a V2 encrypted packet

            -- Until sending "TLS Successfully Established", any messages other than TLSCONN.* and "Query MCU State" are ignored.
         end,
      },
      [1] = {
         name = "Some TLS-like Handshake?",
         dissect_command = function(tree, buf)
            -- Seemingly some TLS-like handshake, untested.
            tree:add_le(body, buf(0, 4)):append_text("handshake type?")
            tree:add_le(body, buf(4, 4)):append_text("handshake data len?")
            local data_len = buf(4, 4):le_uint() - 8
            tree:add_le(body, buf(8, data_len)):append_text("handshake data?")
         end,
         dissect_reply = function(tree, buf)
            -- > SAME structure?
            tree:add_le(body, buf(0, 4)):append_text("handshake type?")
            tree:add_le(body, buf(4, 4)):append_text("handshake data len?")
            local data_len = buf(4, 4):le_uint() - 8
            tree:add_le(body, buf(8, data_len)):append_text("handshake data?")
         end,
      },
      [2] = {
         name = "TLS Successfully Established",
         dissect_command = function(tree, buf)
            -- No args, no reply.
         end,
      },
      [0xE] = {
         category_name = "PROD",
      },
      [0xF] = {
         category_name = "UPFW",
      },
   }
}


function protocol.dissector(buffer, pinfo, tree)
   length = buffer:len()
   if length == 0 then return end

   pinfo.cols.protocol = "Goodix"

   local subtree = tree:add(protocol, buffer(), "Goodix Message Protocol")

   subtree:add_le(cmd0_field, buffer(0,1))
   subtree:add_le(cmd1_field, buffer(0,1))
   subtree:add_le(cmd_continuation, buffer(0,1))

   cmd_val = buffer(0, 1):le_uint()
   cmd0_val, cmd1_val = extract_cmd0_cmd1(cmd_val)

   -- continuation packets (in v1 devices) do not have the same structure as
   -- normal packets:
   --
   -- 1. they do not have a len field, their size is fixed;
   -- 2. the len field in the first non-continuation packet referred to the
   --    size of the actual data after it has been reassembled;
   -- 3. the checksum is only at the end of the last continuation packet.
   --    To find the checksum some inter-packet state must be kept...
   if bit.band(cmd_val, 0x1) == 1 then
      subtree:add_le(body, buffer(1,length - 1)):append_text(" data of a chunked message")
      return
   end

   subtree:add_le(len, buffer(1,2)):append_text(" payload bytes (including checksum)")

   -- leave out the checksum when parsing the actual body
   local body_len = buffer(1,2):le_uint() - 1

   -- if the body_len is greater than the packet buffer size, this is the
   -- first packet of a chunked message, and does not contain the checksum
   if body_len > length - 3 then
      body_len = length - 3
      -- TODO keep some inter-packet state here, like "chunked_payload_len"?
   else
      -- skip command (1 byte) and (2 bytes), and body to get to the actual checksum
      subtree:add_le(cksum, buffer(3 + body_len,1))
   end

   body_buf = buffer(3, body_len):tvb()

   from_host = pinfo.src == Address.ip("1.1.1.1") or tostring(pinfo.src) == "host"

   local cmd_subtree = subtree:add(protocol, body_buf())

   if from_host then
      summary = "Command: " .. get_cmd_name(cmd_val)

      if commands[cmd0_val][cmd1_val] ~= nil then
         commands[cmd0_val][cmd1_val].dissect_command(cmd_subtree, body_buf)
      end
   else
      summary = "Reply: " .. get_cmd_name(cmd_val)

      if commands[cmd0_val][cmd1_val] ~= nil then
         commands[cmd0_val][cmd1_val].dissect_reply(cmd_subtree, body_buf)
      end
   end

   cmd_subtree.text = summary
   pinfo.cols.info = summary
end

DissectorTable.get("tls.port"):add(1, protocol)
DissectorTable.get("usb.product"):add(0x27c65385, protocol)
DissectorTable.get("usb.product"):add(0x27c65042, protocol)

DissectorTable.get("usb.protocol"):add_for_decode_as(protocol)
DissectorTable.get("usb.product"):add_for_decode_as(protocol)
DissectorTable.get("usb.device"):add_for_decode_as(protocol)
