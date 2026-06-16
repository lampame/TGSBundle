const { TelegramClient } = require("telegram");
const { MemorySession } = require("telegram/sessions");
const { Api } = require("telegram/tl");
const { Buffer } = require("buffer");

module.exports = {
    TelegramClient,
    MemorySession,
    Api,
    Buffer
};
