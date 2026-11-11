# Paper-trading demo

A small stock app with fake prices and fake money, used to show GuardFil
protecting an app in two ways with a real model:

- **Built-in agent** (`stockapp/builtin_agent.py`): the app's own agent. It
  runs inside the app with the app's key, and asks GuardFil before every tool
  through the Python client (`@guard`). This is cooperative: GuardFil protects
  the calls the app sends through it.
- **Outside agent** (`outside_agent.py`): it uses the app's API only through
  GuardFil's gateway, holding only a GuardFil token. It runs on a Docker
  network where GuardFil is the only reachable host, and GuardFil holds the
  app's key. This is enforcement: there is no other way in.

Both agents share `agent_loop.py` and ask the model through the model-neutral
broker (`guardfil-broker`, in `internal/broker/`), so the same code runs on OpenAI, Anthropic or Gemini
(`test_model_neutral.py`; live runs use OpenAI only).

Policy (`deployments/example/approval/stockapp-policy.yaml`):

- quotes are allowed;
- the portfolio is filtered;
- orders up to 1,000 are monitored, and larger ones (or ones with no price) ask the owner;
- cancels are monitored;
- withdrawals are blocked.

The catalog bounds quantities and prices, so a negative price cannot make an
order look small. A script stands in for the owner (`owner.py`): it allows
held orders worth under 2,000.

```sh
python3 -I demo/run_demo.py --set demo       # 8 scenarios, real model (about 15 requests)
python3 -I demo/run_demo.py --set redteam    # 6 adversarial scenarios
python3 -I demo/run_demo.py --set probes     # scripted attacks, no model
python3 -I demo/run_demo.py --set all
python3 -m unittest demo.test_model_neutral  # offline, three providers
```

Each run prints every tool call and GuardFil's answer, what the app actually
received, the owner's answers, the decision log and the model cost. It also
writes `demo/last-run.log`. The stack runs on two internal networks:
`gfdemo-apps` (GuardFil and the app) and `gfdemo-agents` (GuardFil and
outside agents). Neither has a route outside.

`GF_DEMO_FAKE_BROKER=<script>` swaps in a scripted model for dry runs of the
plumbing.
