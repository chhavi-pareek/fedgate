"""
FedGate Poison Demo — Innovation 1 Demonstration

Demonstrates reputation-weighted aggregation defending against model poisoning.
Runs federation twice with identical poison injection at Node 2 (Search), round 3:
  - Run 1: reputation weighting ON — trust scores penalise the poisoned node
  - Run 2: reputation weighting OFF — plain FedAvg, no penalty for poisoned node

Side-by-side comparison shows reputation weighting absorbs the attack while plain
FedAvg degrades. Static PNG for academic report. JSON for React dashboard (Phase 6).
Both outputs are derived from identical experimental data.
"""

import sys
import os
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

try:
    from backend.federation import run_federation
except ImportError as e:
    print(f'Import error: {e}')
    print('Ensure tenseal and other dependencies are installed in your environment.')
    sys.exit(1)

POISON_NODE_ID = 2
POISON_ROUND = 3
NUM_ROUNDS = 10
NUM_CLIENTS = 5
RESULTS_DIR = os.path.join(ROOT_DIR, 'experiments', 'results')
SERVICE_NAMES = {0: 'Login', 1: 'Payment', 2: 'Search', 3: 'Profile', 4: 'Admin'}
NODE_COLORS = ['#00d4ff', '#ff6b6b', '#51cf66', '#ffd43b', '#cc5de8']


def run_poison_demo() -> dict:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    print('=' * 60)
    print('  FedGate Poison Demo — Innovation 1 Demonstration')
    print(f'  Poison target: Node {POISON_NODE_ID} (Search) at round {POISON_ROUND}')
    print('  Comparing: Reputation weighting ON vs OFF')
    print('=' * 60)

    print('\nRun 1: Federation WITH reputation weighting (poison active)')
    results_with_rep = run_federation(
        num_clients=NUM_CLIENTS,
        num_rounds=NUM_ROUNDS,
        epsilon=1.0,
        use_reputation=True,
        poison_node_id=POISON_NODE_ID,
        poison_round=POISON_ROUND,
        save_results=True,
        results_dir=RESULTS_DIR
    )

    print('\nRun 2: Federation WITHOUT reputation weighting (poison active)')
    results_without_rep = run_federation(
        num_clients=NUM_CLIENTS,
        num_rounds=NUM_ROUNDS,
        epsilon=1.0,
        use_reputation=False,
        poison_node_id=POISON_NODE_ID,
        poison_round=POISON_ROUND,
        save_results=True,
        results_dir=RESULTS_DIR
    )

    f1_with_rep = [rr['mean_global_f1'] for rr in results_with_rep['round_results']]
    f1_without_rep = [rr['mean_global_f1'] for rr in results_without_rep['round_results']]
    trust_with_rep = [
        rr['trust_scores'].get(POISON_NODE_ID, rr['trust_scores'].get(str(POISON_NODE_ID), 0))
        for rr in results_with_rep['round_results']
    ]

    # Comparison table
    print('\n' + '=' * 60)
    print('  Poison Demo Results')
    print('=' * 60)
    print(f'  {"Round":<5}   {"With Reputation":<17}   {"Without Reputation":<18}   {"Trust (Node 2)":<14}')
    print(f'  {"─" * 5}   {"─" * 17}   {"─" * 18}   {"─" * 14}')
    for i, (f1_w, f1_wo, trust) in enumerate(zip(f1_with_rep, f1_without_rep, trust_with_rep)):
        rnd = i + 1
        marker = ' ★' if rnd == POISON_ROUND else '  '
        suffix = '   ← POISON INJECTED' if rnd == POISON_ROUND else ''
        print(f'  {rnd:>3}{marker}      {f1_w:.4f}              {f1_wo:.4f}              {trust:.3f}{suffix}')

    print(f'\n  ★ = Poison active from this round')
    final_with = float(np.mean(f1_with_rep[-3:]))
    final_without = float(np.mean(f1_without_rep[-3:]))
    defended = final_with - final_without
    final_trust_with = trust_with_rep[-1]

    print(f'\n  Final mean F1 WITH reputation:    {final_with:.4f}')
    print(f'  Final mean F1 WITHOUT reputation: {final_without:.4f}')
    print(f'  F1 defended by reputation:        {defended:+.4f}')
    print(f'\n  Node 2 final trust (with rep):    {final_trust_with:.3f}')
    print(f'  Node 2 final trust (without rep): 1.000 (never penalised)')
    print('=' * 60)

    # Static PNG — three subplots
    rounds = list(range(1, NUM_ROUNDS + 1))

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(16, 6))
    fig.patch.set_facecolor('#0f0f1a')
    fig.suptitle(
        'FedGate: Reputation-Weighted Aggregation vs Plain FedAvg under Poisoning Attack',
        fontsize=14, color='white', y=1.01
    )

    dark_bg = '#1a1a2e'
    spine_color = '#444'

    def style_ax(ax):
        ax.set_facecolor(dark_bg)
        for spine in ax.spines.values():
            spine.set_color(spine_color)
        ax.tick_params(colors='white')
        ax.grid(alpha=0.3, color='#555')

    # Left — convergence comparison
    style_ax(ax1)
    ax1.plot(rounds, f1_with_rep, color='#00d4ff', linewidth=2.5,
             label='With Reputation Weighting')
    ax1.plot(rounds, f1_without_rep, color='#ff6b6b', linewidth=2.5,
             linestyle='--', label='Without Reputation Weighting')
    ax1.axvline(x=POISON_ROUND, color='#ff6b6b', linestyle='--', linewidth=1.5, alpha=0.8,
                label=f'Node {POISON_NODE_ID} poisoned (round {POISON_ROUND})')
    ax1.axvspan(POISON_ROUND, NUM_ROUNDS + 0.5, alpha=0.08, color='red',
                label='Post-poison rounds')
    ax1.set_xlim(1, NUM_ROUNDS)
    ax1.set_ylim(0, 1)
    ax1.set_xlabel('Round', color='white')
    ax1.set_ylabel('Mean Global F1', color='white')
    ax1.set_title('Impact of Reputation Weighting\non Poisoning Attack', fontsize=13, color='white')
    legend1 = ax1.legend(fontsize=7, facecolor=dark_bg, labelcolor='white', edgecolor=spine_color)

    # Middle — Node 2 trust score degradation
    style_ax(ax2)
    ax2.plot(rounds, trust_with_rep, color='#cc5de8', linewidth=2,
             label=f'Node {POISON_NODE_ID} trust score')
    ax2.axvline(x=POISON_ROUND, color='#ff6b6b', linestyle='--', linewidth=1.5, alpha=0.8)
    ax2.axhline(y=0.1, color='#ff6b6b', linestyle='--', alpha=0.7,
                label='Minimum trust floor')
    ax2.fill_between(rounds, trust_with_rep, [0.1] * NUM_ROUNDS,
                     where=[t >= 0.1 for t in trust_with_rep],
                     color='#cc5de8', alpha=0.2)
    # Annotation at poison round
    poison_trust = trust_with_rep[POISON_ROUND - 1]
    ax2.annotate('Poisoned', xy=(POISON_ROUND, poison_trust),
                 xytext=(POISON_ROUND + 1.5, poison_trust + 0.1),
                 color='white', fontsize=9,
                 arrowprops=dict(arrowstyle='->', color='white', lw=1.2))
    ax2.set_xlim(1, NUM_ROUNDS)
    ax2.set_ylim(0, 1)
    ax2.set_xlabel('Round', color='white')
    ax2.set_ylabel('Trust Score', color='white')
    ax2.set_title(f'Node {POISON_NODE_ID} ({SERVICE_NAMES[POISON_NODE_ID]}) Trust Score Degradation',
                  fontsize=13, color='white')
    legend2 = ax2.legend(fontsize=8, facecolor=dark_bg, labelcolor='white', edgecolor=spine_color)

    # Right — per-node final F1 grouped bar chart
    style_ax(ax3)
    node_indices = list(range(NUM_CLIENTS))
    width = 0.35
    x = np.arange(NUM_CLIENTS)
    f1_w_nodes = [results_with_rep['post_federation'][i]['global_f1'] for i in node_indices]
    f1_wo_nodes = [results_without_rep['post_federation'][i]['global_f1'] for i in node_indices]
    bars1 = ax3.bar(x - width / 2, f1_w_nodes, width, color='#00d4ff', alpha=0.85,
                    label='With Reputation')
    bars2 = ax3.bar(x + width / 2, f1_wo_nodes, width, color='#ff6b6b', alpha=0.85,
                    label='Without Reputation')
    ax3.set_xticks(x)
    ax3.set_xticklabels([SERVICE_NAMES[i] for i in node_indices], color='white', fontsize=9)
    ax3.set_ylim(0, 1)
    ax3.set_xlabel('Service Node', color='white')
    ax3.set_ylabel('Final Post-Fed F1', color='white')
    ax3.set_title('Per-Node Final F1:\nWith vs Without Reputation', fontsize=13, color='white')
    legend3 = ax3.legend(fontsize=8, facecolor=dark_bg, labelcolor='white', edgecolor=spine_color)

    plt.tight_layout()

    png_ts_path = os.path.join(RESULTS_DIR, f'poison_demo_{timestamp}.png')
    png_latest_path = os.path.join(RESULTS_DIR, 'poison_demo_latest.png')
    fig.savefig(png_ts_path, dpi=150, bbox_inches='tight', facecolor='#0f0f1a')
    fig.savefig(png_latest_path, dpi=150, bbox_inches='tight', facecolor='#0f0f1a')
    plt.close(fig)
    print(f'Static chart saved to experiments/results/poison_demo_latest.png')

    # Dashboard JSON
    dashboard_data = {
        'generated_at': datetime.now().isoformat(),
        'experiment': 'poison_demo',
        'config': {
            'num_rounds': NUM_ROUNDS,
            'num_clients': NUM_CLIENTS,
            'poison_node_id': POISON_NODE_ID,
            'poison_round': POISON_ROUND,
            'epsilon': 1.0
        },
        'with_reputation': {
            'convergence_curve': [round(f, 4) for f in f1_with_rep],
            'final_mean_f1': round(float(np.mean(f1_with_rep[-3:])), 4),
            'post_fed_f1': {
                str(i): round(results_with_rep['post_federation'][i]['global_f1'], 4)
                for i in range(NUM_CLIENTS)
            },
            'node_trust_history': [round(t, 4) for t in trust_with_rep],
            'final_trust_scores': {
                str(k): round(v, 4)
                for k, v in results_with_rep['final_trust_scores'].items()
            }
        },
        'without_reputation': {
            'convergence_curve': [round(f, 4) for f in f1_without_rep],
            'final_mean_f1': round(float(np.mean(f1_without_rep[-3:])), 4),
            'post_fed_f1': {
                str(i): round(results_without_rep['post_federation'][i]['global_f1'], 4)
                for i in range(NUM_CLIENTS)
            },
            'final_trust_scores': {
                str(k): round(v, 4)
                for k, v in results_without_rep['final_trust_scores'].items()
            }
        },
        'poison_node_id': POISON_NODE_ID,
        'poison_round': POISON_ROUND,
        'service_names': {str(k): v for k, v in SERVICE_NAMES.items()},
        'f1_defended': round(
            float(np.mean(f1_with_rep[-3:])) - float(np.mean(f1_without_rep[-3:])), 4
        )
    }
    json_path = os.path.join(RESULTS_DIR, 'poison_demo_latest.json')
    with open(json_path, 'w') as f:
        json.dump(dashboard_data, f, indent=2)
    print(f'Dashboard JSON saved to experiments/results/poison_demo_latest.json')

    print(f'\nPoison demo complete.')
    print(f'F1 defended by reputation weighting: {defended:+.4f}')
    print('Dashboard JSON ready for Phase 6 React dashboard.')

    return {
        'with_reputation': results_with_rep,
        'without_reputation': results_without_rep,
        'f1_with_rep': f1_with_rep,
        'f1_without_rep': f1_without_rep,
        'trust_with_rep': trust_with_rep,
        'f1_defended': defended
    }


if __name__ == '__main__':
    run_poison_demo()
