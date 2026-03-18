/*
 * Rosalie's Mupen GUI - https://github.com/Rosalie241/RMG
 *  Copyright (C) 2020-2026 Rosalie Wanders <rosalie@mailbox.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3.
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef MCP_MCPBRIDGESERVER_HPP
#define MCP_MCPBRIDGESERVER_HPP

#include <QByteArray>
#include <QHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QList>
#include <QObject>
#include <QSet>
#include <QString>

#include <functional>

#include <RMG-Core/Debugger.hpp>

QT_FORWARD_DECLARE_CLASS(QWebSocket)
QT_FORWARD_DECLARE_CLASS(QWebSocketServer)
QT_FORWARD_DECLARE_CLASS(QTimer)

namespace MCP
{
class McpBridgeServer : public QObject
{
    Q_OBJECT

  public:
    explicit McpBridgeServer(quint16 port = 8765, QObject* parent = nullptr);
    ~McpBridgeServer() override;

    bool Start(void);
    void Stop(void);

    bool IsRunning(void) const;
    quint16 Port(void) const;
    void SetRestartRomHandler(std::function<bool(QString*)> handler);

  signals:
    void ServerError(QString message);

  private slots:
    void onNewConnection(void);
    void onTextMessageReceived(QString message);
    void onSocketDisconnected(void);
    void onEventPump(void);

  private:
    struct EventStreamSubscription
    {
        bool includeVi = false;
        QStringList typeFilters;
        bool hasPcRange = false;
        quint32 pcStart = 0;
        quint32 pcEnd = 0;
    };

    void sendJson(QWebSocket* socket, const QJsonObject& payload) const;
    void broadcastEvent(const CoreDebuggerEvent& event) const;
    QJsonObject processRequest(const QJsonObject& request) const;
    QJsonObject handleReadRam(const QJsonObject& request) const;
    QJsonObject handleWriteRam(const QJsonObject& request) const;
    QJsonObject handleReadRegister(const QJsonObject& request) const;
    QJsonObject handleWriteRegister(const QJsonObject& request) const;
    QJsonObject handleDebuggerState(const QJsonObject& request) const;
    QJsonObject handleCpuSnapshot(const QJsonObject& request) const;
    QJsonObject handleTranslateAddress(const QJsonObject& request) const;
    QJsonObject handleDisassemble(const QJsonObject& request) const;
    QJsonObject handlePauseExecution(const QJsonObject& request) const;
    QJsonObject handleResumeExecution(const QJsonObject& request) const;
    QJsonObject handleResetEmulation(const QJsonObject& request) const;
    QJsonObject handleRestartRom(const QJsonObject& request) const;
    QJsonObject handleStepInstruction(const QJsonObject& request) const;
    QJsonObject handleRunUntil(const QJsonObject& request) const;
    QJsonObject handleStepOver(const QJsonObject& request) const;
    QJsonObject handleStepOut(const QJsonObject& request) const;
    QJsonObject handleAddBreakpoint(const QJsonObject& request) const;
    QJsonObject handleAddWatchpoint(const QJsonObject& request) const;
    QJsonObject handleRemoveBreakpoint(const QJsonObject& request) const;
    QJsonObject handleListBreakpoints(const QJsonObject& request) const;
    QJsonObject handleClearBreakpoints(const QJsonObject& request) const;
    QJsonObject handleLoadSymbols(const QJsonObject& request) const;
    QJsonObject handleClearSymbols(const QJsonObject& request) const;
    QJsonObject handleSymbolStatus(const QJsonObject& request) const;
    QJsonObject handleResolveSymbol(const QJsonObject& request) const;
    QJsonObject handleLookupSymbol(const QJsonObject& request) const;
    QJsonObject handleGetDebugEvents(const QJsonObject& request) const;
    QJsonObject handleConfigureEventStream(const QJsonObject& request);

    static bool tryParseHexU32(QString text, quint32* value);
    static bool tryParseHexU64(QString text, quint64* value);
    static bool tryParseHexBytes(QString text, QByteArray* bytes);
    static QString bytesToHexString(const QByteArray& bytes);
    static QString u32ToHexString(quint32 value);
    static QString u64ToHexString(quint64 value);
    static QString runStateToString(int runState);
    static QString dynacoreToString(int dynacore);
    static QString breakpointFlagsToString(quint32 flags);
    static QJsonArray breakpointKindsToJson(quint32 flags);
    static QJsonArray instructionListToJson(const QJsonArray& instructions);
    static QJsonObject symbolToJson(const CoreDebuggerSymbol& symbol);
    static QJsonObject resolvedSymbolToJson(const CoreDebuggerResolvedSymbol& symbol);
    static QJsonObject eventToJson(const CoreDebuggerEvent& event);
    static QJsonObject makeOkResponse(const QJsonObject& request, const QJsonValue& data);
    static QJsonObject makeErrorResponse(const QJsonObject& request, const QString& message);
    static void copyRequestId(const QJsonObject& request, QJsonObject* response);

    quint16 port;
    QWebSocketServer* server = nullptr;
    QTimer* eventTimer = nullptr;
    QList<QWebSocket*> clients;
    QHash<QWebSocket*, EventStreamSubscription> eventSubscribers;
    quint64 lastBroadcastEventId = 0;
    std::function<bool(QString*)> restartRomHandler;
};
} // namespace MCP

#endif // MCP_MCPBRIDGESERVER_HPP
