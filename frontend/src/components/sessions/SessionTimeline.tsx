import React from 'react';
import { EmailSession } from '../../types/analyzer';
import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Lock,
  Unlock,
  Terminal,
  Shield,
  Key,
  Server,
  Network,
  FileCheck,
} from 'lucide-react';

interface SessionTimelineProps {
  session: EmailSession;
}

interface TimelineEvent {
  id: string;
  title: string;
  subtitle?: string;
  status: 'SUCCESS' | 'WARNING' | 'ERROR' | 'INFO';
  icon: React.ComponentType<{ className?: string }>;
  timestamp?: string | null;
  details?: React.ReactNode;
}

export const SessionTimeline: React.FC<SessionTimelineProps> = ({ session }) => {
  const events: TimelineEvent[] = [];

  // 1. TCP Connection (Always observed)
  events.push({
    id: 'tcp-handshake',
    title: 'TCP Connection Established',
    subtitle: `${session.source_ip || session.src_ip}:${session.source_port ?? session.src_port} → ${session.destination_ip || session.dst_ip}:${session.destination_port ?? session.dst_port}`,
    status: 'SUCCESS',
    icon: Network,
    timestamp: session.first_seen || session.timestamp_first,
    details: (
      <div className="text-[11px] text-slate-400 font-mono flex items-center gap-2">
        <span className="px-1.5 py-0.5 rounded bg-[#080d16] border border-[#1e293b]">
          Stream #{session.tcp_stream_id ?? session.session_index}
        </span>
        <span>{session.transport_protocol || 'TCP'} 3-Way Handshake</span>
      </div>
    ),
  });

  const isImplicitTls =
    session.encryption_mode === 'IMPLICIT_TLS' ||
    (!session.starttls_requested && !session.starttls_supported && session.is_encrypted);

  // 2. Email Protocol Identification (if not implicit TLS or if explicitly identified)
  if (!isImplicitTls || session.protocol !== 'UNKNOWN') {
    const isUnknown = session.protocol === 'UNKNOWN';
    events.push({
      id: 'protocol-ident',
      title: isUnknown ? 'Protocol Undetermined' : `${session.protocol.toUpperCase()} Protocol Identified`,
      subtitle: isUnknown
        ? 'Traffic characteristics did not match standard SMTP/IMAP/POP3 signatures'
        : 'Identified via packet heuristics & protocol framing',
      status: isUnknown ? 'WARNING' : 'INFO',
      icon: Server,
      details: session.protocol_evidence ? (
        <div className="text-[11px] text-slate-400 font-mono bg-[#080d16] p-2 rounded border border-[#1e293b] break-words">
          Evidence: {Array.isArray(session.protocol_evidence) ? session.protocol_evidence.join(', ') : session.protocol_evidence}
        </div>
      ) : undefined,
    });
  }

  // 3. Cleartext Protocol Greeting / Command (e.g. EHLO/HELO) - Only observed in non-implicit TLS
  if (!isImplicitTls && session.protocol !== 'UNKNOWN') {
    const isSmtp = session.protocol.toUpperCase().startsWith('SMTP');
    const isPop3 = session.protocol.toUpperCase().startsWith('POP3');

    let commandLabel = 'Plaintext Greeting / Capabilities';
    if (isSmtp) commandLabel = 'SMTP EHLO / HELO Handshake';
    else if (isPop3) commandLabel = 'POP3 Greeting / STLS Probe';
    else commandLabel = 'IMAP CAPABILITY / Greeting';

    events.push({
      id: 'protocol-greeting',
      title: commandLabel,
      subtitle: session.starttls_supported
        ? 'Server advertised cryptographic upgrade capability'
        : 'Server greeted client over cleartext stream',
      status: 'INFO',
      icon: Terminal,
      details: session.starttls_evidence ? (
        <div className="text-[11px] text-sky-300 font-mono bg-[#080d16] p-2 rounded border border-[#1e293b] break-all">
          {session.starttls_evidence}
        </div>
      ) : undefined,
    });
  }

  // 4. STARTTLS / STLS Upgrade Negotiation (Observed only if requested or advertised)
  if (session.starttls_requested || session.starttls_supported || session.encryption_mode === 'STARTTLS_UPGRADE' || session.encryption_mode === 'FAILED_UPGRADE') {
    const isFailed = session.encryption_mode === 'FAILED_UPGRADE' || (session.starttls_requested && !session.tls_upgrade_detected && !session.is_encrypted);
    events.push({
      id: 'starttls-negotiation',
      title: isFailed ? 'STARTTLS Upgrade Failed / Refused' : 'STARTTLS Upgrade Negotiated',
      subtitle: isFailed
        ? 'Client requested encryption upgrade but TLS handshake was not completed'
        : 'Client issued upgrade command (STARTTLS/STLS) and received affirmative response',
      status: isFailed ? 'ERROR' : 'SUCCESS',
      icon: isFailed ? AlertTriangle : Shield,
      details: (
        <div className="text-[11px] font-mono grid grid-cols-2 gap-2 bg-[#080d16] p-2 rounded border border-[#1e293b]">
          <div>
            <span className="text-slate-500">Advertised: </span>
            <span className={session.starttls_supported ? 'text-emerald-400 font-bold' : 'text-slate-400'}>
              {session.starttls_supported ? 'YES' : 'NO'}
            </span>
          </div>
          <div>
            <span className="text-slate-500">Requested: </span>
            <span className={session.starttls_requested ? 'text-sky-400 font-bold' : 'text-slate-400'}>
              {session.starttls_requested ? 'YES' : 'NO'}
            </span>
          </div>
        </div>
      ),
    });
  }

  // 5. TLS ClientHello (Observed if client_hello_seen or encrypted or tls_version)
  if (session.client_hello_seen || session.is_encrypted || session.tls_version) {
    events.push({
      id: 'tls-client-hello',
      title: 'TLS ClientHello',
      subtitle: session.sni ? `SNI Hostname: ${session.sni}` : 'Client cryptographic parameters & cipher list proposed',
      status: 'INFO',
      icon: Lock,
      details: (
        <div className="text-[11px] font-mono space-y-1 bg-[#080d16] p-2 rounded border border-[#1e293b]">
          {session.sni && (
            <div>
              <span className="text-slate-500">Server Name (SNI): </span>
              <span className="text-sky-300 font-bold">{session.sni}</span>
            </div>
          )}
          {session.alpn && (
            <div>
              <span className="text-slate-500">ALPN: </span>
              <span className="text-slate-300">{session.alpn}</span>
            </div>
          )}
          <div>
            <span className="text-slate-500">Proposed TLS Mode: </span>
            <span className="text-slate-300">{session.tls_version || 'TLS 1.2+'}</span>
          </div>
        </div>
      ),
    });
  }

  // 6. TLS ServerHello (Observed if server_hello_seen or cipher_suite or is_encrypted)
  if (session.server_hello_seen || session.cipher_suite || (session.is_encrypted && session.tls_version)) {
    const isWeakTls = session.tls_version === 'TLS 1.0' || session.tls_version === 'TLS 1.1' || session.tls_version === 'SSLv3';
    events.push({
      id: 'tls-server-hello',
      title: 'TLS ServerHello & Cipher Agreement',
      subtitle: `Negotiated ${session.tls_version || 'TLS'} with ${session.forward_secrecy ? 'Perfect Forward Secrecy' : 'Static Key Exchange'}`,
      status: isWeakTls ? 'WARNING' : 'SUCCESS',
      icon: Key,
      details: (
        <div className="text-[11px] font-mono space-y-1 bg-[#080d16] p-2 rounded border border-[#1e293b]">
          <div>
            <span className="text-slate-500">Agreed Version: </span>
            <span className={`font-bold ${isWeakTls ? 'text-amber-400' : 'text-emerald-400'}`}>
              {session.tls_version || 'Unknown'}
            </span>
          </div>
          <div>
            <span className="text-slate-500">Selected Cipher: </span>
            <span className="text-sky-300 break-all">{session.cipher_suite || 'Unknown'}</span>
          </div>
          {session.key_exchange && (
            <div>
              <span className="text-slate-500">Key Exchange: </span>
              <span className="text-slate-300">{session.key_exchange}</span>
            </div>
          )}
        </div>
      ),
    });
  }

  // 7. X.509 Certificate Exchange (Observed if certificate_seen)
  if (session.certificate_seen) {
    events.push({
      id: 'certificate-exchange',
      title: 'X.509 Server Certificate Delivered',
      subtitle: 'Server sent Certificate handshake message containing X.509 chain',
      status: 'SUCCESS',
      icon: FileCheck,
      details: (
        <div className="text-[11px] font-mono bg-[#080d16] p-2 rounded border border-[#1e293b] text-slate-300">
          Peer certificate captured and parsed for cryptographic signature, key size, and validity.
        </div>
      ),
    });
  }

  // 8. TLS Alert / Handshake Failure (Observed if tls_alerts present)
  if (session.tls_alerts && session.tls_alerts !== '[]' && session.tls_alerts !== '""') {
    events.push({
      id: 'tls-alert',
      title: 'TLS Alert Record Encountered',
      subtitle: 'Alert protocol message transmitted during cryptographic session',
      status: 'ERROR',
      icon: XCircle,
      details: (
        <div className="text-[11px] font-mono bg-rose-950/40 text-rose-300 p-2 rounded border border-rose-900/60 break-all">
          {typeof session.tls_alerts === 'string' ? session.tls_alerts : JSON.stringify(session.tls_alerts)}
        </div>
      ),
    });
  }

  // 9. Encrypted Application Traffic OR Cleartext Data Transmission
  if (session.is_encrypted) {
    events.push({
      id: 'encrypted-comm',
      title: 'Encrypted Application Data Stream',
      subtitle: 'Symmetric session established. All email payloads and authentication credentials protected.',
      status: 'SUCCESS',
      icon: Lock,
      timestamp: session.last_seen || session.timestamp_last,
      details: (
        <div className="text-[11px] font-mono text-emerald-400 bg-emerald-950/30 p-2 rounded border border-emerald-900/50">
          Handshake Completed · {session.packet_count} packets ({session.byte_count} bytes) secured
        </div>
      ),
    });
  } else {
    events.push({
      id: 'plaintext-comm',
      title: 'Cleartext Data Transmission',
      subtitle: 'Session concluded without cryptographic protection.',
      status: 'WARNING',
      icon: Unlock,
      timestamp: session.last_seen || session.timestamp_last,
      details: (
        <div className="text-[11px] font-mono text-amber-400 bg-amber-950/30 p-2 rounded border border-amber-900/50">
          UNENCRYPTED: Credentials and email content are vulnerable to passive network interception and sniffing.
        </div>
      ),
    });
  }

  const getStatusColor = (status: TimelineEvent['status']) => {
    switch (status) {
      case 'SUCCESS':
        return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
      case 'WARNING':
        return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
      case 'ERROR':
        return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
      case 'INFO':
      default:
        return 'text-sky-400 border-sky-500/30 bg-sky-500/10';
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Observed Session Flow & Timeline
        </h4>
        <span className="text-[11px] font-mono text-slate-500">
          {events.length} observed milestones
        </span>
      </div>

      <div className="relative pl-6 space-y-4 before:absolute before:top-2 before:bottom-2 before:left-[11px] before:w-[2px] before:bg-[#1e293b]">
        {events.map((evt) => {
          const Icon = evt.icon;
          return (
            <div key={evt.id} className="relative group">
              <div
                className={`absolute -left-6 top-0 w-6 h-6 rounded-full border flex items-center justify-center ${getStatusColor(
                  evt.status
                )} shadow-sm z-10`}
              >
                <Icon className="w-3.5 h-3.5" />
              </div>

              <div className="p-3 rounded-lg bg-[#0d1422] border border-[#1e293b] space-y-1.5">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h5 className="text-xs font-semibold text-slate-200">{evt.title}</h5>
                    {evt.subtitle && (
                      <p className="text-[11px] text-slate-400 mt-0.5">{evt.subtitle}</p>
                    )}
                  </div>
                  {evt.timestamp && (
                    <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
                      {evt.timestamp.slice(11, 19)}
                    </span>
                  )}
                </div>

                {evt.details && <div className="mt-2 pt-2 border-t border-[#182338]">{evt.details}</div>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
