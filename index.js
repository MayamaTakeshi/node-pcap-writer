/**
 * The Pcap writer.
 */
'use strict';

var _ = require('lodash');
var fs = require('fs');

var GlobalHeader = require('./lib/header/globalhdr');
var PacketHeader = require('./lib/header/packethdr');
var Constants = require('./lib/constants');

/**
 * Initialize new pcap writer.
 * Also writes Global header in the file.
 * @param {String} file  Name of the file to be crated with file path.
 */
function PcapWriter(file, snaplen, linktype) {
  this._fs = fs.createWriteStream(file);
  var options = {};
  if (snaplen) { options.snaplen = snaplen; }
  if (linktype) { options.linktype = linktype; }
  // write global header.
  this._fs.write(new Buffer((new GlobalHeader(options)).toString(), Constants.HEADER_ENCODING));
}

/**
 * Write new packet in file
 * @param  {Buffer} pkt Buffer containing data.
 * @param  {Number} ts  Timestamp [optional].
 */
PcapWriter.prototype.writePacket = function(pkt, ts) {
  var ph = new PacketHeader({
    tv_sec: pkt.header.timestampSeconds,
    tv_usec: pkt.header.timestampMicroseconds,
    caplen: pkt.header.capturedLength,
    len: pkt.header.originalLength 
  });
  // write packet header
  this._fs.write(new Buffer(ph.toString(), Constants.HEADER_ENCODING));
  // write packet data
  this._fs.write(pkt.data);
};

/**
 * Close file stream.
 */
PcapWriter.prototype.close = function() {
  return this._fs.end();
};

module.exports = PcapWriter;
