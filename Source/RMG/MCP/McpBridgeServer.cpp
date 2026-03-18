/*
 * Rosalie's Mupen GUI - https://github.com/Rosalie241/RMG
 *  Copyright (C) 2020-2026 Rosalie Wanders <rosalie@mailbox.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3.
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "McpBridgeServer.hpp"

#include <QHostAddress>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QStringList>
#include <QWebSocket>
#include <QWebSocketServer>

#include <RMG-Core/Debugger.hpp>
#include <RMG-Core/Error.hpp>
#include <RMG-Core/m64p/api/m64p_types.h>

#include <array>
#include <utility>
#include <vector>

namespace
{
constexpr quint32 kMaxReadSize = 4096;
constexpr quint32 kMaxDisassemblyInstructions = 256;
constexpr quint32 kMaxStepCount = 1024;

QString requestRegisterName(const QJsonObject& request)
{
    QString registerName = request.value(QStringLiteral("register")).toString();
    if (registerName.isEmpty())
    {
        registerName = request.value(QStringLiteral("register_name")).toString();
    }

    return registerName.trimmed();
}
} // namespace

using namespace MCP;

McpBridgeServer::McpBridgeServer(quint16 port, QObject* parent) : QObject(parent), port(port)
{
    this->server = new QWebSocketServer(QStringLiteral("MCP Bridge"), QWebSocketServer::NonSecureMode, this);
    connect(this->server, &QWebSocketServer::newConnection, this, &McpBridgeServer::onNewConnection);
}

McpBridgeServer::~McpBridgeServer()
{
    this->Stop();
}

bool McpBridgeServer::Start(void)
{
    if (this->server->isListening())
    {
        return true;
    }

    bool ret = this->server->listen(QHostAddress::LocalHost, this->port);
    if (!ret)
    {
        emit this->ServerError(QStringLiteral("Failed to start MCP bridge on port %1: %2")
                                   .arg(this->port)
                                   .arg(this->server->errorString()));
    }

    return ret;
}

void McpBridgeServer::Stop(void)
{
    for (QWebSocket* socket : std::as_const(this->clients))
    {
        if (socket == nullptr)
        {
            continue;
        }

        socket->close();
        socket->deleteLater();
    }

    this->clients.clear();

    if (this->server != nullptr &&
        this->server->isListening())
    {
        this->server->close();
    }
}

bool McpBridgeServer::IsRunning(void) const
{
    return this->server != nullptr && this->server->isListening();
}

quint16 McpBridgeServer::Port(void) const
{
    return this->port;
}

void McpBridgeServer::onNewConnection(void)
{
    while (this->server->hasPendingConnections())
    {
        QWebSocket* socket = this->server->nextPendingConnection();
        if (socket == nullptr)
        {
            continue;
        }

        this->clients.append(socket);

        connect(socket, &QWebSocket::textMessageReceived, this, &McpBridgeServer::onTextMessageReceived);
        connect(socket, &QWebSocket::disconnected, this, &McpBridgeServer::onSocketDisconnected);
    }
}

void McpBridgeServer::onTextMessageReceived(QString message)
{
    QWebSocket* socket = qobject_cast<QWebSocket*>(sender());
    if (socket == nullptr)
    {
        return;
    }

    QJsonParseError parseError;
    QJsonDocument document = QJsonDocument::fromJson(message.toUtf8(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject())
    {
        this->sendJson(socket,
                       QJsonObject{
                           {QStringLiteral("status"), QStringLiteral("error")},
                           {QStringLiteral("error"),
                            QStringLiteral("Invalid JSON request: %1").arg(parseError.errorString())},
                       });
        return;
    }

    this->sendJson(socket, this->processRequest(document.object()));
}

void McpBridgeServer::onSocketDisconnected(void)
{
    QWebSocket* socket = qobject_cast<QWebSocket*>(sender());
    if (socket == nullptr)
    {
        return;
    }

    this->clients.removeAll(socket);
    socket->deleteLater();
}

void McpBridgeServer::sendJson(QWebSocket* socket, const QJsonObject& payload) const
{
    if (socket == nullptr)
    {
        return;
    }

    socket->sendTextMessage(QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
}

QJsonObject McpBridgeServer::processRequest(const QJsonObject& request) const
{
    QString action = request.value(QStringLiteral("action")).toString().trimmed();
    if (action.isEmpty())
    {
        return makeErrorResponse(request, QStringLiteral("Missing required field: action"));
    }

    if (action == QStringLiteral("ping"))
    {
        return makeOkResponse(request, QStringLiteral("pong"));
    }

    if (action == QStringLiteral("read_ram"))
    {
        return this->handleReadRam(request);
    }

    if (action == QStringLiteral("write_ram"))
    {
        return this->handleWriteRam(request);
    }

    if (action == QStringLiteral("read_register"))
    {
        return this->handleReadRegister(request);
    }

    if (action == QStringLiteral("write_register"))
    {
        return this->handleWriteRegister(request);
    }

    if (action == QStringLiteral("debugger_state"))
    {
        return this->handleDebuggerState(request);
    }

    if (action == QStringLiteral("cpu_snapshot"))
    {
        return this->handleCpuSnapshot(request);
    }

    if (action == QStringLiteral("translate_address"))
    {
        return this->handleTranslateAddress(request);
    }

    if (action == QStringLiteral("disassemble"))
    {
        return this->handleDisassemble(request);
    }

    if (action == QStringLiteral("pause_execution"))
    {
        return this->handlePauseExecution(request);
    }

    if (action == QStringLiteral("resume_execution"))
    {
        return this->handleResumeExecution(request);
    }

    if (action == QStringLiteral("step_instruction"))
    {
        return this->handleStepInstruction(request);
    }

    if (action == QStringLiteral("add_breakpoint"))
    {
        return this->handleAddBreakpoint(request);
    }

    if (action == QStringLiteral("remove_breakpoint"))
    {
        return this->handleRemoveBreakpoint(request);
    }

    if (action == QStringLiteral("list_breakpoints"))
    {
        return this->handleListBreakpoints(request);
    }

    if (action == QStringLiteral("clear_breakpoints"))
    {
        return this->handleClearBreakpoints(request);
    }

    return makeErrorResponse(request, QStringLiteral("Unsupported action: %1").arg(action));
}

QJsonObject McpBridgeServer::handleReadRam(const QJsonObject& request) const
{
    QString addressText = request.value(QStringLiteral("address")).toString();
    int sizeValue = request.value(QStringLiteral("size")).toInt(-1);

    quint32 address = 0;
    if (!tryParseHexU32(addressText, &address))
    {
        return makeErrorResponse(request, QStringLiteral("Invalid address: %1").arg(addressText));
    }

    if (sizeValue <= 0 || sizeValue > static_cast<int>(kMaxReadSize))
    {
        return makeErrorResponse(request,
                                 QStringLiteral("Invalid size. Expected 1..%1 bytes.")
                                     .arg(static_cast<int>(kMaxReadSize)));
    }

    std::vector<uint8_t> bytes;
    if (!CoreDebuggerReadMemory(address, static_cast<uint32_t>(sizeValue), bytes))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    QByteArray payload(reinterpret_cast<const char*>(bytes.data()), static_cast<qsizetype>(bytes.size()));
    return makeOkResponse(request, bytesToHexString(payload));
}

QJsonObject McpBridgeServer::handleWriteRam(const QJsonObject& request) const
{
    QString addressText = request.value(QStringLiteral("address")).toString();
    QString dataText = request.value(QStringLiteral("data")).toString();
    if (dataText.isEmpty())
    {
        dataText = request.value(QStringLiteral("bytes_hex")).toString();
    }

    quint32 address = 0;
    if (!tryParseHexU32(addressText, &address))
    {
        return makeErrorResponse(request, QStringLiteral("Invalid address: %1").arg(addressText));
    }

    QByteArray bytes;
    if (!tryParseHexBytes(dataText, &bytes) || bytes.isEmpty())
    {
        return makeErrorResponse(request, QStringLiteral("Invalid data payload. Expected a non-empty hexadecimal string."));
    }

    std::vector<uint8_t> payload(bytes.begin(), bytes.end());
    if (!CoreDebuggerWriteMemory(address, payload))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    QJsonObject response{
        {QStringLiteral("address"), u32ToHexString(address)},
        {QStringLiteral("size"), static_cast<int>(bytes.size())},
        {QStringLiteral("data"), bytesToHexString(bytes)},
    };
    return makeOkResponse(request, response);
}

QJsonObject McpBridgeServer::handleReadRegister(const QJsonObject& request) const
{
    QString registerName = requestRegisterName(request);
    if (registerName.isEmpty())
    {
        return makeErrorResponse(request, QStringLiteral("Missing required field: register"));
    }

    uint64_t value = 0;
    if (!CoreDebuggerReadCpuRegister(registerName.toStdString(), value))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    return makeOkResponse(request, u64ToHexString(value));
}

QJsonObject McpBridgeServer::handleWriteRegister(const QJsonObject& request) const
{
    QString registerName = requestRegisterName(request);
    QString valueText = request.value(QStringLiteral("value")).toString();
    if (valueText.isEmpty())
    {
        valueText = request.value(QStringLiteral("value_hex")).toString();
    }

    if (registerName.isEmpty())
    {
        return makeErrorResponse(request, QStringLiteral("Missing required field: register"));
    }

    quint64 value = 0;
    if (!tryParseHexU64(valueText, &value))
    {
        return makeErrorResponse(request, QStringLiteral("Invalid value: %1").arg(valueText));
    }

    if (!CoreDebuggerWriteCpuRegister(registerName.toStdString(), value))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    return makeOkResponse(request, u64ToHexString(value));
}

QJsonObject McpBridgeServer::handleDebuggerState(const QJsonObject& request) const
{
    CoreDebuggerState state;
    if (!CoreDebuggerGetState(state))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    QJsonObject payload{
        {QStringLiteral("run_state"), runStateToString(state.runState)},
        {QStringLiteral("run_state_raw"), state.runState},
        {QStringLiteral("previous_pc"), u32ToHexString(state.previousPc)},
        {QStringLiteral("breakpoint_count"), state.breakpointCount},
        {QStringLiteral("dynacore"), dynacoreToString(state.dynacore)},
        {QStringLiteral("dynacore_raw"), state.dynacore},
        {QStringLiteral("next_interrupt"), u32ToHexString(state.nextInterrupt)},
    };

    return makeOkResponse(request, payload);
}

QJsonObject McpBridgeServer::handleCpuSnapshot(const QJsonObject& request) const
{
    static constexpr std::array<const char*, 32> kGprNames = {
        "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
        "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
        "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
        "t8", "t9", "k0", "k1", "gp", "sp", "s8", "ra",
    };
    static constexpr std::array<const char*, 32> kCop0Names = {
        "index", "random", "entrylo0", "entrylo1", "context", "pagemask", "wired", "cop0_7",
        "badvaddr", "count", "entryhi", "compare", "status", "cause", "epc", "prid",
        "config", "lladdr", "watchlo", "watchhi", "xcontext", "cop0_21", "cop0_22", "cop0_23",
        "cop0_24", "cop0_25", "perr", "cacheerr", "taglo", "taghi", "errorepc", "cop0_31",
    };

    QJsonObject gprObject;
    for (const char* name : kGprNames)
    {
        uint64_t value = 0;
        if (!CoreDebuggerReadCpuRegister(name, value))
        {
            return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
        }

        gprObject.insert(QString::fromLatin1(name), u64ToHexString(value));
    }

    QJsonObject cop0Object;
    for (const char* name : kCop0Names)
    {
        uint64_t value = 0;
        if (!CoreDebuggerReadCpuRegister(name, value))
        {
            return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
        }

        cop0Object.insert(QString::fromLatin1(name), u64ToHexString(value));
    }

    uint64_t pc = 0;
    uint64_t hi = 0;
    uint64_t lo = 0;
    if (!CoreDebuggerReadCpuRegister("pc", pc) ||
        !CoreDebuggerReadCpuRegister("hi", hi) ||
        !CoreDebuggerReadCpuRegister("lo", lo))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    CoreDebuggerState state;
    if (!CoreDebuggerGetState(state))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    QJsonObject payload{
        {QStringLiteral("pc"), u64ToHexString(pc)},
        {QStringLiteral("hi"), u64ToHexString(hi)},
        {QStringLiteral("lo"), u64ToHexString(lo)},
        {QStringLiteral("gpr"), gprObject},
        {QStringLiteral("cop0"), cop0Object},
        {QStringLiteral("state"),
         QJsonObject{
             {QStringLiteral("run_state"), runStateToString(state.runState)},
             {QStringLiteral("previous_pc"), u32ToHexString(state.previousPc)},
             {QStringLiteral("breakpoint_count"), state.breakpointCount},
             {QStringLiteral("dynacore"), dynacoreToString(state.dynacore)},
             {QStringLiteral("next_interrupt"), u32ToHexString(state.nextInterrupt)},
         }},
    };

    return makeOkResponse(request, payload);
}

QJsonObject McpBridgeServer::handleTranslateAddress(const QJsonObject& request) const
{
    QString addressText = request.value(QStringLiteral("address")).toString();
    quint32 address = 0;
    if (!tryParseHexU32(addressText, &address))
    {
        return makeErrorResponse(request, QStringLiteral("Invalid address: %1").arg(addressText));
    }

    quint32 physicalAddress = 0;
    if (!CoreDebuggerVirtualToPhysical(address, physicalAddress))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    QJsonObject payload{
        {QStringLiteral("virtual_address"), u32ToHexString(address)},
        {QStringLiteral("physical_address"), u32ToHexString(physicalAddress)},
    };
    return makeOkResponse(request, payload);
}

QJsonObject McpBridgeServer::handleDisassemble(const QJsonObject& request) const
{
    QString addressText = request.value(QStringLiteral("address")).toString();
    int countValue = request.value(QStringLiteral("count")).toInt(0);
    if (countValue <= 0)
    {
        countValue = request.value(QStringLiteral("instruction_count")).toInt(0);
    }

    quint32 address = 0;
    if (!tryParseHexU32(addressText, &address))
    {
        return makeErrorResponse(request, QStringLiteral("Invalid address: %1").arg(addressText));
    }

    if (countValue <= 0 || countValue > static_cast<int>(kMaxDisassemblyInstructions))
    {
        return makeErrorResponse(request,
                                 QStringLiteral("Invalid instruction count. Expected 1..%1.")
                                     .arg(static_cast<int>(kMaxDisassemblyInstructions)));
    }

    std::vector<CoreDebuggerInstruction> instructions;
    if (!CoreDebuggerDisassemble(address, static_cast<uint32_t>(countValue), instructions))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    QJsonArray payload;
    for (const CoreDebuggerInstruction& instruction : instructions)
    {
        const QString mnemonic = QString::fromStdString(instruction.mnemonic).trimmed();
        const QString arguments = QString::fromStdString(instruction.arguments).trimmed();
        payload.append(QJsonObject{
            {QStringLiteral("address"), u32ToHexString(instruction.address)},
            {QStringLiteral("physical_address"), u32ToHexString(instruction.physicalAddress)},
            {QStringLiteral("word"), u32ToHexString(instruction.word)},
            {QStringLiteral("mnemonic"), mnemonic},
            {QStringLiteral("arguments"), arguments},
            {QStringLiteral("text"),
             arguments.isEmpty() ? mnemonic : QStringLiteral("%1 %2").arg(mnemonic, arguments)},
        });
    }

    return makeOkResponse(request, payload);
}

QJsonObject McpBridgeServer::handlePauseExecution(const QJsonObject& request) const
{
    if (!CoreDebuggerPauseExecution())
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    CoreDebuggerState state;
    if (!CoreDebuggerGetState(state))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    return makeOkResponse(request, QJsonObject{{QStringLiteral("run_state"), runStateToString(state.runState)}});
}

QJsonObject McpBridgeServer::handleResumeExecution(const QJsonObject& request) const
{
    if (!CoreDebuggerResumeExecution())
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    return makeOkResponse(request, QJsonObject{{QStringLiteral("run_state"), QStringLiteral("running")}});
}

QJsonObject McpBridgeServer::handleStepInstruction(const QJsonObject& request) const
{
    int countValue = request.value(QStringLiteral("count")).toInt(1);
    if (countValue <= 0 || countValue > static_cast<int>(kMaxStepCount))
    {
        return makeErrorResponse(request,
                                 QStringLiteral("Invalid step count. Expected 1..%1.")
                                     .arg(static_cast<int>(kMaxStepCount)));
    }

    quint32 pc = 0;
    if (!CoreDebuggerStepInstructions(static_cast<uint32_t>(countValue), pc))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    return makeOkResponse(request,
                          QJsonObject{
                              {QStringLiteral("count"), countValue},
                              {QStringLiteral("pc"), u32ToHexString(pc)},
                              {QStringLiteral("run_state"), QStringLiteral("paused")},
                          });
}

QJsonObject McpBridgeServer::handleAddBreakpoint(const QJsonObject& request) const
{
    QString addressText = request.value(QStringLiteral("address")).toString();
    QString endAddressText = request.value(QStringLiteral("end_address")).toString();
    if (endAddressText.isEmpty())
    {
        endAddressText = request.value(QStringLiteral("endAddress")).toString();
    }

    quint32 address = 0;
    if (!tryParseHexU32(addressText, &address))
    {
        return makeErrorResponse(request, QStringLiteral("Invalid address: %1").arg(addressText));
    }

    quint32 endAddress = address;
    if (!endAddressText.isEmpty() && !tryParseHexU32(endAddressText, &endAddress))
    {
        return makeErrorResponse(request, QStringLiteral("Invalid end_address: %1").arg(endAddressText));
    }

    quint32 flags = 0;
    QJsonArray kinds = request.value(QStringLiteral("kinds")).toArray();
    if (kinds.isEmpty())
    {
        const QString kind = request.value(QStringLiteral("kind")).toString().trimmed().toLower();
        if (!kind.isEmpty())
        {
            kinds.append(kind);
        }
    }

    if (kinds.isEmpty())
    {
        flags |= M64P_BKP_FLAG_EXEC;
    }
    else
    {
        for (const QJsonValue& value : kinds)
        {
            const QString kind = value.toString().trimmed().toLower();
            if (kind == QStringLiteral("execute") || kind == QStringLiteral("exec") || kind == QStringLiteral("x"))
            {
                flags |= M64P_BKP_FLAG_EXEC;
            }
            else if (kind == QStringLiteral("read") || kind == QStringLiteral("r"))
            {
                flags |= M64P_BKP_FLAG_READ;
            }
            else if (kind == QStringLiteral("write") || kind == QStringLiteral("w"))
            {
                flags |= M64P_BKP_FLAG_WRITE;
            }
            else
            {
                return makeErrorResponse(request, QStringLiteral("Unsupported breakpoint kind: %1").arg(kind));
            }
        }
    }

    if (request.value(QStringLiteral("enabled")).toBool(true))
    {
        flags |= M64P_BKP_FLAG_ENABLED;
    }

    if (request.value(QStringLiteral("log")).toBool(false))
    {
        flags |= M64P_BKP_FLAG_LOG;
    }

    int breakpointIndex = -1;
    if (!CoreDebuggerAddBreakpoint(address, endAddress, flags, breakpointIndex))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    return makeOkResponse(request,
                          QJsonObject{
                              {QStringLiteral("index"), breakpointIndex},
                              {QStringLiteral("address"), u32ToHexString(address)},
                              {QStringLiteral("end_address"), u32ToHexString(endAddress)},
                              {QStringLiteral("flags"), breakpointFlagsToString(flags)},
                              {QStringLiteral("kinds"), breakpointKindsToJson(flags)},
                          });
}

QJsonObject McpBridgeServer::handleRemoveBreakpoint(const QJsonObject& request) const
{
    QString addressText = request.value(QStringLiteral("address")).toString();
    quint32 address = 0;
    if (!tryParseHexU32(addressText, &address))
    {
        return makeErrorResponse(request, QStringLiteral("Invalid address: %1").arg(addressText));
    }

    if (!CoreDebuggerRemoveBreakpoint(address))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    return makeOkResponse(request, QJsonObject{{QStringLiteral("address"), u32ToHexString(address)}});
}

QJsonObject McpBridgeServer::handleListBreakpoints(const QJsonObject& request) const
{
    std::vector<CoreDebuggerBreakpoint> breakpoints;
    if (!CoreDebuggerListBreakpoints(breakpoints))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    CoreDebuggerState state;
    if (!CoreDebuggerGetState(state))
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    QJsonArray payload;
    for (const CoreDebuggerBreakpoint& breakpoint : breakpoints)
    {
        payload.append(QJsonObject{
            {QStringLiteral("address"), u32ToHexString(breakpoint.address)},
            {QStringLiteral("end_address"), u32ToHexString(breakpoint.endAddress)},
            {QStringLiteral("flags"), breakpointFlagsToString(breakpoint.flags)},
            {QStringLiteral("kinds"), breakpointKindsToJson(breakpoint.flags)},
            {QStringLiteral("enabled"), (breakpoint.flags & M64P_BKP_FLAG_ENABLED) != 0},
            {QStringLiteral("log"), (breakpoint.flags & M64P_BKP_FLAG_LOG) != 0},
        });
    }

    return makeOkResponse(request,
                          QJsonObject{
                              {QStringLiteral("managed_breakpoints"), payload},
                              {QStringLiteral("managed_count"), static_cast<int>(payload.size())},
                              {QStringLiteral("core_count"), state.breakpointCount},
                          });
}

QJsonObject McpBridgeServer::handleClearBreakpoints(const QJsonObject& request) const
{
    if (!CoreDebuggerClearBreakpoints())
    {
        return makeErrorResponse(request, QString::fromStdString(CoreGetError()));
    }

    return makeOkResponse(request, QJsonObject{{QStringLiteral("cleared"), true}});
}

bool McpBridgeServer::tryParseHexU32(QString text, quint32* value)
{
    if (value == nullptr)
    {
        return false;
    }

    text = text.trimmed();
    if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        text = text.mid(2);
    }

    bool ok = false;
    uint parsedValue = text.toUInt(&ok, 16);
    if (!ok)
    {
        return false;
    }

    *value = static_cast<quint32>(parsedValue);
    return true;
}

bool McpBridgeServer::tryParseHexU64(QString text, quint64* value)
{
    if (value == nullptr)
    {
        return false;
    }

    text = text.trimmed();
    if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        text = text.mid(2);
    }

    bool ok = false;
    qulonglong parsedValue = text.toULongLong(&ok, 16);
    if (!ok)
    {
        return false;
    }

    *value = static_cast<quint64>(parsedValue);
    return true;
}

bool McpBridgeServer::tryParseHexBytes(QString text, QByteArray* bytes)
{
    if (bytes == nullptr)
    {
        return false;
    }

    text = text.trimmed();
    if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        text = text.mid(2);
    }

    if (text.isEmpty() || (text.size() % 2) != 0)
    {
        return false;
    }

    QByteArray raw = QByteArray::fromHex(text.toLatin1());
    if (raw.isEmpty())
    {
        return false;
    }

    *bytes = raw;
    return true;
}

QString McpBridgeServer::bytesToHexString(const QByteArray& bytes)
{
    return QStringLiteral("0x%1").arg(QString::fromLatin1(bytes.toHex().toUpper()));
}

QString McpBridgeServer::u32ToHexString(quint32 value)
{
    return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper().rightJustified(8, QLatin1Char('0')));
}

QString McpBridgeServer::u64ToHexString(quint64 value)
{
    return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper().rightJustified(16, QLatin1Char('0')));
}

QString McpBridgeServer::runStateToString(int runState)
{
    switch (runState)
    {
        case M64P_DBG_RUNSTATE_PAUSED:
            return QStringLiteral("paused");
        case M64P_DBG_RUNSTATE_STEPPING:
            return QStringLiteral("stepping");
        case M64P_DBG_RUNSTATE_RUNNING:
            return QStringLiteral("running");
        default:
            return QStringLiteral("unknown");
    }
}

QString McpBridgeServer::dynacoreToString(int dynacore)
{
    switch (dynacore)
    {
        case 0:
            return QStringLiteral("pure_interpreter");
        case 1:
            return QStringLiteral("cached_interpreter");
        default:
            return QStringLiteral("dynarec");
    }
}

QString McpBridgeServer::breakpointFlagsToString(quint32 flags)
{
    QStringList parts;
    if ((flags & M64P_BKP_FLAG_ENABLED) != 0)
    {
        parts.append(QStringLiteral("enabled"));
    }
    if ((flags & M64P_BKP_FLAG_EXEC) != 0)
    {
        parts.append(QStringLiteral("execute"));
    }
    if ((flags & M64P_BKP_FLAG_READ) != 0)
    {
        parts.append(QStringLiteral("read"));
    }
    if ((flags & M64P_BKP_FLAG_WRITE) != 0)
    {
        parts.append(QStringLiteral("write"));
    }
    if ((flags & M64P_BKP_FLAG_LOG) != 0)
    {
        parts.append(QStringLiteral("log"));
    }

    return parts.join(QStringLiteral("|"));
}

QJsonArray McpBridgeServer::breakpointKindsToJson(quint32 flags)
{
    QJsonArray kinds;
    if ((flags & M64P_BKP_FLAG_EXEC) != 0)
    {
        kinds.append(QStringLiteral("execute"));
    }
    if ((flags & M64P_BKP_FLAG_READ) != 0)
    {
        kinds.append(QStringLiteral("read"));
    }
    if ((flags & M64P_BKP_FLAG_WRITE) != 0)
    {
        kinds.append(QStringLiteral("write"));
    }

    return kinds;
}

QJsonArray McpBridgeServer::instructionListToJson(const QJsonArray& instructions)
{
    return instructions;
}

QJsonObject McpBridgeServer::makeOkResponse(const QJsonObject& request, const QJsonValue& data)
{
    QJsonObject response{
        {QStringLiteral("status"), QStringLiteral("ok")},
        {QStringLiteral("data"), data},
    };
    copyRequestId(request, &response);
    return response;
}

QJsonObject McpBridgeServer::makeErrorResponse(const QJsonObject& request, const QString& message)
{
    QJsonObject response{
        {QStringLiteral("status"), QStringLiteral("error")},
        {QStringLiteral("error"), message},
    };
    copyRequestId(request, &response);
    return response;
}

void McpBridgeServer::copyRequestId(const QJsonObject& request, QJsonObject* response)
{
    if (response == nullptr)
    {
        return;
    }

    if (request.contains(QStringLiteral("id")))
    {
        response->insert(QStringLiteral("id"), request.value(QStringLiteral("id")));
    }
}
