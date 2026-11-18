# Segurança / Security

## Português

O RansomGuard roda com privilégio alto: o agente é um serviço com direito de administrador em servidores de
arquivos, e o painel distribui a política que manda os agentes bloquear IPs e negar contas. Trate o painel como
sistema administrativo:

- acesso só de quem administra;
- porta 5001 aberta apenas para a rede dos servidores e dos administradores;
- backup da pasta de dados, que guarda a identidade da instalação.

Para relatar uma vulnerabilidade, use **Security → Report a vulnerability** neste repositório. Se a opção não
estiver disponível, abra uma issue **sem detalhes da falha**, pedindo um canal privado. Não publique credenciais,
endereços nem dados de ambientes reais.

Informe a versão e o SHA-256 do instalador, um cenário mínimo, o resultado esperado e o observado, e o impacto. A
manutenção é voluntária, sem SLA. Uma correção vale a partir da release que a contém; versões anteriores não são
corrigidas retroativamente.

Veja o [modelo de segurança](docs/pt-br/seguranca.md) e [Proteção e limites](docs/pt-br/protecao-e-limites.md).
Avalie primeiro em laboratório e num servidor de teste: nenhum teste nosso substitui a validação na sua rede.

## English

RansomGuard runs with high privilege: the agent is a service with administrator rights on file servers, and the
dashboard distributes the policy that tells agents to block IPs and deny accounts. Treat the dashboard as an
administrative system:

- access only for administrators;
- port 5001 open only to the servers' and administrators' network;
- back up the data folder, which holds the installation identity.

To report a vulnerability, use **Security → Report a vulnerability** in this repository. If that option is not
available, open an issue **without vulnerability details**, asking for a private channel. Do not publish
credentials, addresses or data from real environments.

Include the installer version and SHA-256, a minimal scenario, expected and observed behavior, and impact.
Maintenance is voluntary, with no SLA. A fix applies from the release that contains it; earlier versions are not
patched retroactively.

See the [security model](docs/en/security.md) and [Protection and limits](docs/en/protection-and-limits.md).
Evaluate in a lab and on a test server first: none of our tests replaces validation on your network.
