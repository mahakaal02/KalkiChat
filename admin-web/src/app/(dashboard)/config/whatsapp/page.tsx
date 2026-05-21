import { api } from '@/lib/api';
import { WhatsAppForm } from '@/components/WhatsAppForm';

type WhatsAppCfg = { phone_e164: string; message_template: string };

export default async function WhatsAppConfigPage() {
  const r = await api.internal<WhatsAppCfg>('/v1/admin/config/whatsapp');
  const cfg: WhatsAppCfg = r.ok ? r.data : { phone_e164: '', message_template: '' };
  return (
    <section className="space-y-5">
      <h1 className="text-2xl font-semibold">WhatsApp onboarding</h1>
      <p className="text-sm text-gray-400 max-w-2xl">
        The phone number and message below are used when a new user taps
        “Request Login”. The mobile and web clients fetch this config every
        time, so any change here takes effect <strong>immediately</strong>.
        We do <strong>not</strong> use the WhatsApp Business API — this is a
        plain <code>wa.me</code> deep link.
      </p>
      <WhatsAppForm initial={cfg} />
    </section>
  );
}
