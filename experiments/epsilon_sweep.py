"""
FedGate Epsilon Sweep Experiment

Runs the full federation pipeline across 6 epsilon values to quantify the
privacy-performance tradeoff. Lower epsilon = stronger DP noise = lower F1.
epsilon=inf represents the no-privacy baseline (noise scale effectively zero).

Outputs:
  - Static PNG saved for academic report (two-subplot: tradeoff curve + convergence)
  - JSON saved for React dashboard consumption (Phase 6)
  Both are derived from identical experimental data.
"""

import sys
import os
import json
import csv
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

try:
    from backend.federation import run_federation
except ImportError as e:
    print(f"Import error: {e}")
    print("Ensure tenseal and other dependencies are installed in your environment.")
    sys.exit(1)

EPSILON_VALUES = [0.01, 0.1, 0.5, 1.0, 5.0, float('inf')]
NUM_ROUNDS = 10
NUM_CLIENTS = 5
RESULTS_DIR = os.path.join(ROOT_DIR, 'experiments', 'results')
SERVICE_NAMES = {0: 'Login', 1: 'Payment', 2: 'Search', 3: 'Profile', 4: 'Admin'}
NODE_COLORS = ['#00d4ff', '#ff6b6b', '#51cf66', '#ffd43b', '#cc5de8']


def run_epsilon_sweep() -> dict:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    print('=' * 60)
    print('  FedGate Epsilon Sweep Experiment')
    print('  Testing epsilon values: [0.01, 0.1, 0.5, 1.0, 5.0, inf]')
    print(f'  Rounds per run: {NUM_ROUNDS} | Reputation weighting: ON')
    print('=' * 60)

    sweep_results = []
    for eps in EPSILON_VALUES:
        actual_eps = 1e9 if eps == float('inf') else eps
        display_eps = 'inf (no DP)' if eps == float('inf') else str(eps)
        print(f'\nRunning epsilon = {display_eps}...')
        results = run_federation(
            num_clients=NUM_CLIENTS,
            num_rounds=NUM_ROUNDS,
            epsilon=actual_eps,
            use_reputation=True,
            save_results=True,
            results_dir=RESULTS_DIR
        )
        round1_f1 = results['round_results'][0]['mean_global_f1']
        round10_f1 = results['round_results'][-1]['mean_global_f1']
        noise_magnitude = 1.0 / actual_eps if actual_eps < 1e8 else 0.0
        print(f'  Round 1 F1: {round1_f1:.4f} | Round 10 F1: {round10_f1:.4f} | Noise magnitude: {noise_magnitude:.4f}')
        sweep_results.append({
            'epsilon': eps,
            'display_epsilon': display_eps,
            'actual_epsilon': actual_eps,
            'mean_final_f1': results['mean_improvement'] + np.mean([
                results['pre_federation'][i]['global_f1'] for i in range(NUM_CLIENTS)
            ]),
            'mean_improvement': results['mean_improvement'],
            'pre_fed_mean_f1': np.mean([
                results['pre_federation'][i]['global_f1'] for i in range(NUM_CLIENTS)
            ]),
            'post_fed_mean_f1': np.mean([
                results['post_federation'][i]['global_f1'] for i in range(NUM_CLIENTS)
            ]),
            'per_node_post_f1': {
                i: results['post_federation'][i]['global_f1']
                for i in range(NUM_CLIENTS)
            },
            'convergence_curve': [
                rr['mean_global_f1'] for rr in results['round_results']
            ],
            'final_trust_scores': results['final_trust_scores'],
            'run_id': results['run_id']
        })
        print(f'  Post-fed mean F1: {sweep_results[-1]["post_fed_mean_f1"]:.4f} | Improvement: {results["mean_improvement"]:+.4f}')

    # Find minimum viable epsilon
    min_viable_epsilon = None
    for sr in sweep_results:
        if sr['post_fed_mean_f1'] >= 0.70 and sr['epsilon'] != float('inf'):
            if min_viable_epsilon is None or sr['epsilon'] < min_viable_epsilon:
                min_viable_epsilon = sr['epsilon']

    # Summary table
    print('\n' + '=' * 60)
    print('  Epsilon Sweep Results')
    print('=' * 60)
    print(f'  {"Epsilon":<13}  {"Pre-Fed F1":<12}  {"Post-Fed F1":<12}  {"Improvement":<12}  Viable?')
    print(f'  {"─" * 13}  {"─" * 12}  {"─" * 12}  {"─" * 12}  {"─" * 7}')
    for sr in sweep_results:
        viable = 'YES' if sr['post_fed_mean_f1'] >= 0.70 and sr['epsilon'] != float('inf') else 'NO'
        imp_str = f'{sr["mean_improvement"]:+.4f}'
        print(
            f'  {sr["display_epsilon"]:<13}  {sr["pre_fed_mean_f1"]:.4f}        '
            f'{sr["post_fed_mean_f1"]:.4f}        {imp_str:<12}  {viable}'
        )
    if min_viable_epsilon is not None:
        print(f'\n  Minimum viable epsilon (post-fed F1 >= 0.70): {min_viable_epsilon}')
    else:
        print('\n  Minimum viable epsilon (post-fed F1 >= 0.70): None found')
    print('=' * 60)

    # Static PNG
    x_labels = ['0.01', '0.1', '0.5', '1.0', '5.0', 'inf\n(no DP)']
    x_pos = list(range(len(EPSILON_VALUES)))
    post_f1_vals = [sr['post_fed_mean_f1'] for sr in sweep_results]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.patch.set_facecolor('#0f0f1a')
    fig.suptitle('FedGate: Privacy vs Performance Analysis', fontsize=16, color='white', y=1.01)

    # Left subplot
    ax1.set_facecolor('#1a1a2e')
    ax1.plot(x_pos, post_f1_vals, color='#00d4ff', linewidth=2.5, marker='o', markersize=8,
             label='Mean post-fed F1', zorder=5)

    for i in range(NUM_CLIENTS):
        node_f1 = [sr['per_node_post_f1'][i] for sr in sweep_results]
        ax1.plot(x_pos, node_f1, color=NODE_COLORS[i], linewidth=1, alpha=0.5,
                 linestyle='--', label=SERVICE_NAMES[i])

    if min_viable_epsilon is not None:
        viable_idx = [sr['epsilon'] for sr in sweep_results].index(min_viable_epsilon)
        ax1.axvline(x=viable_idx, color='#ff6b6b', linestyle='--', linewidth=1.5,
                    label=f'Min viable ε', zorder=4)
        ax1.axhspan(0, 1, xmin=0, xmax=(viable_idx) / (len(x_pos) - 1),
                    alpha=0.1, color='red', label='Privacy too costly')
        ax1.axhspan(0, 1, xmin=(viable_idx) / (len(x_pos) - 1), xmax=1,
                    alpha=0.1, color='green', label='Operational range')

    ax1.axhline(y=0.70, color='#51cf66', linestyle=':', alpha=0.7,
                label='Viability threshold (F1=0.70)')
    ax1.set_xticks(x_pos)
    ax1.set_xticklabels(x_labels, color='white')
    ax1.set_ylim(0, 1)
    ax1.set_xlabel('Epsilon (DP budget)', color='white')
    ax1.set_ylabel('Post-Federation Mean Global F1', color='white')
    ax1.set_title('Privacy-Performance Tradeoff (FedGate)', fontsize=14, color='white')
    ax1.tick_params(colors='white')
    ax1.spines['bottom'].set_color('#444')
    ax1.spines['left'].set_color('#444')
    ax1.spines['top'].set_color('#444')
    ax1.spines['right'].set_color('#444')
    ax1.grid(alpha=0.3, color='#555')
    legend = ax1.legend(fontsize=7, facecolor='#1a1a2e', labelcolor='white',
                        edgecolor='#444', loc='lower right')

    # Right subplot — convergence curves
    ax2.set_facecolor('#1a1a2e')
    rounds = list(range(1, NUM_ROUNDS + 1))
    colors_gradient = plt.cm.cool(np.linspace(0, 1, len(EPSILON_VALUES)))
    for idx, sr in enumerate(sweep_results):
        ax2.plot(rounds, sr['convergence_curve'], color=colors_gradient[idx],
                 linewidth=1.8, label=sr['display_epsilon'])
    ax2.set_xlabel('Round', color='white')
    ax2.set_ylabel('Mean Global F1', color='white')
    ax2.set_title('Convergence Rate by Epsilon', fontsize=14, color='white')
    ax2.tick_params(colors='white')
    ax2.spines['bottom'].set_color('#444')
    ax2.spines['left'].set_color('#444')
    ax2.spines['top'].set_color('#444')
    ax2.spines['right'].set_color('#444')
    ax2.grid(alpha=0.3, color='#555')
    legend2 = ax2.legend(title='Epsilon', fontsize=8, facecolor='#1a1a2e',
                         labelcolor='white', edgecolor='#444', title_fontsize=8)
    legend2.get_title().set_color('white')

    plt.tight_layout()

    png_ts_path = os.path.join(RESULTS_DIR, f'epsilon_sweep_{timestamp}.png')
    png_latest_path = os.path.join(RESULTS_DIR, 'epsilon_sweep_latest.png')
    fig.savefig(png_ts_path, dpi=150, bbox_inches='tight', facecolor='#0f0f1a')
    fig.savefig(png_latest_path, dpi=150, bbox_inches='tight', facecolor='#0f0f1a')
    plt.close(fig)
    print(f'Static chart saved to experiments/results/epsilon_sweep_latest.png')

    # CSV
    csv_path = os.path.join(RESULTS_DIR, f'epsilon_sweep_{timestamp}.csv')
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['epsilon', 'display_epsilon', 'pre_fed_mean_f1', 'post_fed_mean_f1',
                         'mean_improvement', 'node_0_f1', 'node_1_f1', 'node_2_f1',
                         'node_3_f1', 'node_4_f1', 'min_viable'])
        for sr in sweep_results:
            writer.writerow([
                sr['epsilon'], sr['display_epsilon'],
                round(sr['pre_fed_mean_f1'], 4), round(sr['post_fed_mean_f1'], 4),
                round(sr['mean_improvement'], 4),
                round(sr['per_node_post_f1'][0], 4), round(sr['per_node_post_f1'][1], 4),
                round(sr['per_node_post_f1'][2], 4), round(sr['per_node_post_f1'][3], 4),
                round(sr['per_node_post_f1'][4], 4),
                sr['epsilon'] == min_viable_epsilon
            ])

    # Dashboard JSON
    dashboard_data = {
        'generated_at': datetime.now().isoformat(),
        'experiment': 'epsilon_sweep',
        'config': {
            'num_rounds': NUM_ROUNDS,
            'num_clients': NUM_CLIENTS,
            'epsilon_values': [str(e) for e in EPSILON_VALUES]
        },
        'min_viable_epsilon': min_viable_epsilon,
        'viability_threshold': 0.70,
        'results': [
            {
                'epsilon': sr['epsilon'] if sr['epsilon'] != float('inf') else 'inf',
                'display_epsilon': sr['display_epsilon'],
                'pre_fed_mean_f1': round(sr['pre_fed_mean_f1'], 4),
                'post_fed_mean_f1': round(sr['post_fed_mean_f1'], 4),
                'mean_improvement': round(sr['mean_improvement'], 4),
                'per_node_post_f1': {
                    str(k): round(v, 4)
                    for k, v in sr['per_node_post_f1'].items()
                },
                'convergence_curve': [round(f, 4) for f in sr['convergence_curve']],
                'is_min_viable': sr['epsilon'] == min_viable_epsilon
            }
            for sr in sweep_results
        ],
        'service_names': SERVICE_NAMES
    }
    json_path = os.path.join(RESULTS_DIR, 'epsilon_sweep_latest.json')
    with open(json_path, 'w') as f:
        json.dump(dashboard_data, f, indent=2)
    print(f'Dashboard JSON saved to experiments/results/epsilon_sweep_latest.json')

    print('\nEpsilon sweep complete.')
    return sweep_results


if __name__ == '__main__':
    run_epsilon_sweep()
