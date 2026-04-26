const mongoose = require('mongoose');

const scanLogSchema = new mongoose.Schema({
    target_endpoint: { type: String, required: true },
    vulnerability_type: { type: String, required: true },
    status: { type: String, required: true },
    remediation_code_generated: { type: String },
    timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('ScanLog', scanLogSchema);