-- Cypress USB HID bootloader protocol dissector for Wireshark
--
-- Copyright (C) 2016 Forest Crossman <cyrozap@gmail.com>
--
-- Based on the SysClk LWLA protocol dissector for Wireshark,
-- Copyright (C) 2014 Daniel Elstner <daniel.kitta@gmail.com>
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, see <http://www.gnu.org/licenses/>.

-- Usage: wireshark -X lua_script:cybootloader.lua
--
-- It is not advisable to install this dissector globally, since
-- it will try to interpret the communication of any USB device
-- using the vendor-specific interface class.

-- Create custom protocol for the Cypress USB HID bootloader.
p_cybootloader = Proto("cybootloader", "Cypress Semiconductor USB HID bootloader protocol")

-- Return codes
local statuses = {
    [0x00] = "CYRET_SUCCESS",
    [0x03] = "BOOTLOADER_ERR_LENGTH",
    [0x04] = "BOOTLOADER_ERR_DATA",
    [0x05] = "BOOTLOADER_ERR_CMD",
    [0x08] = "BOOTLOADER_ERR_CHECKSUM",
    [0x09] = "BOOTLOADER_ERR_ARRAY",
    [0x0a] = "BOOTLOADER_ERR_ROW",
    [0x0c] = "BOOTLOADER_ERR_APP",
    [0x0d] = "BOOTLOADER_ERR_ACTIVE",
    [0x0e] = "BOOTLOADER_ERR_CALLBACK",
    [0x0f] = "BOOTLOADER_ERR_UNK"
}

-- Bootloader commands
local commands = {
    [0x38] = "Enter Bootloader",
    [0x32] = "Get Flash Size",
    [0x39] = "Program Row",
    [0x34] = "Erase Row",
    [0x3a] = "Get Row Checksum",
    [0x31] = "Verify Application Checksum",
    [0x37] = "Send Data",
    [0x35] = "Sync bootloader",
    [0x3b] = "Exit Bootloader",
    [0x3c] = "Get Metadata",
    [0x33] = "Get Application Status",
    [0x36] = "Set Active Application",
    [0x45] = "Verify Row"
}

-- Create the fields exhibited by the protocol.
p_cybootloader.fields.sop = ProtoField.uint8("cybootloader.sop", "Start of Packet", base.HEX)
p_cybootloader.fields.status = ProtoField.uint8("cybootloader.status", "Status/Error Code", base.HEX, statuses)
p_cybootloader.fields.command = ProtoField.uint8("cybootloader.command", "Command ID", base.HEX, commands)
p_cybootloader.fields.length = ProtoField.uint16("cybootloader.length", "Data Length", base.DEC)
p_cybootloader.fields.data = ProtoField.bytes("cybootloader.data", "Packet Data")
p_cybootloader.fields.checksum = ProtoField.uint16("cybootloader.checksum", "Packet Checksum", base.HEX)
p_cybootloader.fields.eop = ProtoField.uint8("cybootloader.eop", "End of Packet", base.HEX)

p_cybootloader.fields.unknown = ProtoField.bytes("cybootloader.unknown", "Unidentified message data")

-- Referenced USB URB dissector fields.
local f_urb_type = Field.new("usb.urb_type")
local f_transfer_type = Field.new("usb.transfer_type")
local f_endpoint = Field.new("usb.endpoint_number.endpoint")
local f_len = Field.new("frame.len")

-- Insert warning for undecoded leftover data.
local function warn_undecoded(tree, range)
    local item = tree:add(p_cybootloader.fields.unknown, range)
    item:add_expert_info(PI_UNDECODED, PI_WARN, "Leftover data")
end

-- Dissect bootloader command messages.
local function dissect_bootloader_command(buffer, pinfo, tree)
    local sop = buffer(0,1)
    local command = buffer(1,1)
    local length = buffer(2,2)
    local checksum = buffer(4+length:le_uint(),2)
    local eop = buffer(4+length:le_uint()+2,1)

    local subtree = tree:add(p_cybootloader, buffer(0,7+length:le_uint()), "Cypress Bootloader Command")

    subtree:add(p_cybootloader.fields.sop, sop)
    subtree:add(p_cybootloader.fields.command, command)
    subtree:add_le(p_cybootloader.fields.length, length)
    if (length:le_uint() > 0) then
        local data = buffer(4,length:le_uint())
        subtree:add(p_cybootloader.fields.data, data)
    end
    subtree:add_le(p_cybootloader.fields.checksum, checksum)
    subtree:add(p_cybootloader.fields.eop, eop)
end

-- Dissect bootloader response messages.
local function dissect_bootloader_response(buffer, pinfo, tree)
    local sop = buffer(0,1)
    local status = buffer(1,1)
    local length = buffer(2,2)
    local checksum = buffer(4+length:le_uint(),2)
    local eop = buffer(4+length:le_uint()+2,1)

    local subtree = tree:add(p_cybootloader, buffer(0,7+length:le_uint()), "Cypress Bootloader Response")

    subtree:add(p_cybootloader.fields.sop, sop)
    subtree:add(p_cybootloader.fields.status, status)
    subtree:add_le(p_cybootloader.fields.length, length)
    if (length:le_uint() > 0) then
        local data = buffer(4,length:le_uint())
        subtree:add(p_cybootloader.fields.data, data)
    end
    subtree:add_le(p_cybootloader.fields.checksum, checksum)
    subtree:add(p_cybootloader.fields.eop, eop)
end

-- Main bootloader dissector function.
function p_cybootloader.dissector(buffer, pinfo, tree)
    local transfer_type = tonumber(tostring(f_transfer_type()))
    local endpoint = tonumber(tostring(f_endpoint()))
    local urb_type = tonumber(tostring(f_urb_type()))

    -- Interrupt transfers with the bootloader SOP byte
    local sop = buffer(0,1):uint()
    if ( (transfer_type == 1) and (sop == 0x01) ) then
        -- We only care about the IN and OUT endpoints
        if ( (urb_type == 0x53) and (endpoint == 1) ) then
            dissect_bootloader_command(buffer, pinfo, tree)
        elseif ( (urb_type == 0x43) and (endpoint == 2) ) then
            dissect_bootloader_response(buffer, pinfo, tree)
        else
            return 0
        end
    else
        return 0
    end
end

function p_cybootloader.init()
    local usb_product_dissectors = DissectorTable.get("usb.product")

    -- Dissection by vendor+product ID requires that Wireshark can get the
    -- the device descriptor.  Making a USB device available inside VirtualBox
    -- will make it inaccessible from Linux, so Wireshark cannot fetch the
    -- descriptor by itself.  However, it is sufficient if the VirtualBox
    -- guest requests the descriptor once while Wireshark is capturing.
    usb_product_dissectors:add(0x04b4f13b, p_cybootloader)

    -- Addendum: Protocol registration based on product ID does not always
    -- work as desired.  Register the protocol on the interface class instead.
    -- The downside is that it would be a bad idea to put this into the global
    -- configuration, so one has to make do with -X lua_script: for now.
    -- local usb_control_dissectors = DissectorTable.get("usb.control")

    -- For some reason the "unknown" class ID is sometimes 0xFF and sometimes
    -- 0xFFFF.  Register both to make it work all the time.
    -- usb_control_dissectors:add(0xFF, p_cybootloader)
    -- usb_control_dissectors:add(0xFFFF, p_cybootloader)
end
