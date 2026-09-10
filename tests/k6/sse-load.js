// Charge côté client de la passerelle SSE.
//
// k6 ne dispose ici d'aucun module SSE ni Redis : il ne peut ni lire un flux
// incrémentalement, ni publier sur le bus. Il porte donc ce qu'il fait le mieux
// — ouvrir et tenir des milliers de connexions persistantes — pendant que la
// commande `eventgen` injecte le trafic réellement chiffré :
//
//   make dev-keys                        # émet .dev/tickets.json
//   make load-test                       # ce script
//   make load-events                     # dans un second terminal, pendant le palier
//
// Les tickets sont pré-signés en EdDSA par « make dev-keys », k6 ne sachant pas
// signer. Un ticket factice serait rejeté en HTTP 401 par la passerelle dès lors
// que le pilote d'authentification JWT est actif, c'est-à-dire toujours hors
// mode de démonstration.

import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';
import { SharedArray } from 'k6/data';

const tickets = new SharedArray('tickets', () =>
  JSON.parse(open(__ENV.TICKETS_FILE || '../../.dev/tickets.json')),
);

const BASE_URL = __ENV.TARGET_URL || 'http://127.0.0.1:18080';
const HOLD = __ENV.HOLD || '30s';
const PEAK_VUS = Number(__ENV.PEAK_VUS || 150);

// Un flux SSE sain ne se termine jamais de lui-même : l'expiration du délai est
// donc le résultat attendu. Une fin prématurée signale au contraire que la
// passerelle a fermé le flux — client lent, quota atteint ou panne.
const REQUEST_TIMEOUT = 1050;

const streamsHeld = new Counter('sse_streams_held');
const streamsClosedEarly = new Counter('sse_streams_closed_early');
const healthLatency = new Trend('sse_health_latency', true);

export const options = {
  scenarios: {
    persistent_streams: {
      executor: 'ramping-vus',
      exec: 'holdStream',
      startVUs: 0,
      stages: [
        { duration: '10s', target: PEAK_VUS },
        { duration: '60s', target: PEAK_VUS },
        { duration: '5s', target: 0 },
      ],
      gracefulRampDown: '10s',
    },
    // La passerelle doit rester nerveuse pendant le fan-out chiffré.
    responsiveness: {
      executor: 'constant-arrival-rate',
      exec: 'probeHealth',
      rate: 20,
      timeUnit: '1s',
      duration: '75s',
      preAllocatedVUs: 5,
    },
  },
  thresholds: {
    sse_streams_closed_early: ['count==0'],
    sse_health_latency: ['p(95)<50'],
    checks: ['rate>0.99'],
  },
};

export function holdStream() {
  const ticket = tickets[__VU % tickets.length];
  const res = http.get(`${BASE_URL}/v1/events?ticket=${ticket}`, {
    headers: { Accept: 'text/event-stream' },
    timeout: HOLD,
    tags: { name: 'sse_stream' },
  });

  const held = res.error_code === REQUEST_TIMEOUT;
  check(res, { 'flux maintenu ouvert pendant toute la fenêtre': () => held });
  if (held) {
    streamsHeld.add(1);
  } else {
    streamsClosedEarly.add(1);
  }
}

export function probeHealth() {
  const res = http.get(`${BASE_URL}/healthz`, { tags: { name: 'healthz' } });
  healthLatency.add(res.timings.duration);
  check(res, { 'healthz répond 200': (r) => r.status === 200 });
}
