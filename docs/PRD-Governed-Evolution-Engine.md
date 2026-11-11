# PRD — Governed Evolution Engine

**Produto:** psyche-agents  
**Módulo:** Evolutionary Engine  
**Versão:** 1.0.0  
**Status:** Proposed  
**Categoria:** Agentic Systems / Autonomous Software Evolution / Runtime Governance

## 1. Visão do produto

Desenvolver um motor de evolução para sistemas multiagentes capaz de identificar limitações operacionais, propor melhorias, sintetizar novas capacidades e atualizar componentes sem comprometer a integridade, a segurança ou a disponibilidade do sistema.

Os agentes podem participar ativamente da evolução do ecossistema, mas não recebem autoridade irrestrita para executar código gerado por modelos de linguagem.

Toda evolução passa por proposta, validação isolada, aprovação humana, ativação atômica e recuperação verificável.

**Princípio fundamental:** a IA pode propor como o sistema deve evoluir, mas não pode conceder a si própria autorização para modificar o ambiente de produção.

## 2. Problema

Sistemas multiagentes que geram e executam código dinamicamente apresentam riscos: código incorreto ou vulnerável, correções inadequadas, regressões, atualizações concorrentes inconsistentes, ausência de rollback, alteração indevida de políticas e falhas em componentes compartilhados.

A solução separa três responsabilidades:

1. **Criação:** agentes propõem e sintetizam melhorias.
2. **Governança:** mecanismos independentes verificam e autorizam mudanças.
3. **Execução:** o runtime ativa somente versões aprovadas e verificadas.

## 3. Objetivos

### Objetivo principal

Implementar evolução contínua que permita desenvolver novas capacidades e corrigir problemas de maneira controlada, verificável, auditável e reversível.

### Objetivos específicos

- Detectar falhas e limitações em agentes, ferramentas e comportamentos.
- Transformar evidências em propostas estruturadas.
- Permitir síntese de código por modelos locais ou externos.
- Validar candidatos em ambientes isolados.
- Verificar compatibilidade, contratos, segurança e desempenho.
- Exigir aprovação humana antes da ativação em produção.
- Realizar hot-swap atômico.
- Preservar versões anteriores e permitir rollback.
- Registrar decisões, artefatos e evidências.

## 4. Atores e responsabilidades

| Ator | Responsabilidade |
|---|---|
| Magician Agent | Identificar oportunidades e preparar candidatos |
| Shadow Agent | Testar candidatos adversarialmente |
| Sage Agent | Verificar evidências, resultados e proveniência |
| Hero Agent | Coordenar progresso dentro de limites autorizados |
| Superego | Aplicar políticas e restrições de segurança |
| Ego | Coordenar o processo e suas transições |
| Evolution Controller | Administrar propostas, aprovações e ativações |
| Human Approver | Autorizar ou rejeitar mudanças |
| Runtime | Executar versões aprovadas |

Nenhum agente deve acumular criação, validação, autorização e ativação sem separação de responsabilidades.

## 5. Fluxo principal

### 5.1 Evolution Proposal

Transformar uma necessidade em uma proposta verificável. As origens incluem exceções, falhas recorrentes, testes adversariais, ausência de ferramenta, degradação de desempenho, mudanças contratuais e novas necessidades.

Cada proposta contém:

- ProposalID: identificador único.
- TargetID: componente afetado.
- CurrentVersion e CandidateVersion.
- FailureEvidence: evidências que motivaram a mudança.
- ExpectedOutcome: resultado esperado.
- ChangeDescription: alterações propostas.
- RiskAssessment: avaliação de risco.
- ArtifactHash: hash SHA-256 do artefato candidato imutável.
- CreatedBy e CreatedAt.

Criar uma proposta nunca altera produção.

### 5.2 Isolated Validation

Executar o candidato exclusivamente em ambiente isolado. A validação contempla:

| Categoria | Verificação |
|---|---|
| Functional | Testes unitários e funcionais |
| Integration | Integração com ferramentas existentes |
| Contract | Compatibilidade de entradas e saídas |
| Security | Vulnerabilidades, permissões e dependências |
| Adversarial | Tentativas de exploração conduzidas pela Sombra |
| Performance | Latência, CPU e memória |
| Reliability | Comportamento diante de falhas |
| Regression | Preservação das funcionalidades anteriores |
| Provenance | Integridade e origem dos artefatos |

O sandbox deve ter limites de CPU, memória e tempo; rede restrita; credenciais temporárias de privilégio mínimo; filesystem isolado; nenhum acesso direto à produção; logs e limpeza controlada.

O ValidationReport registra ValidationID, hash validado, testes, evidências, falhas, métricas e resultado. A validação só pode aprovar exatamente o hash do candidato armazenado.

### 5.3 Human Approval

O aprovador recebe descrição da mudança, comparação de versões, relatório de validação, resultados adversariais, impacto, riscos e planos de ativação e recuperação.

Decisões: Approve, Reject e Request Changes.

Regras:

1. Aprovação somente por identidade autenticada em serviço confiável.
2. Aplicar separação de funções quando exigida.
3. Vincular aprovação a ProposalID, ArtifactHash e ValidationID.
4. Alteração do artefato após validação invalida a aprovação.
5. Mudanças em governança e segurança exigem autoridade específica.
6. Um LLM jamais substitui a aprovação humana.

A assinatura HMAC deste projeto é uma implementação de referência para a fronteira de aprovação; o serviço chamador deve autenticar a pessoa antes de emitir o token.

### 5.4 Atomic Activation / Compare-and-Swap

Antes da substituição, verificar versão ativa, geração do registry, hash do artefato, aprovação, integridade e disponibilidade de rollback.

Condições:

- CurrentVersion = ExpectedVersion
- RegistryGeneration = ExpectedGeneration

Se qualquer condição falhar, abortar. Preparar a versão, verificar novamente os artefatos, executar CAS, publicar a referência da versão, verificar saúde e registrar o resultado.

A troca é atômica para os consumidores do registry. Execuções que já utilizam versão anterior devem poder concluir seu ciclo de vida sem referências inválidas.

### 5.5 Recovery / Rollback

Antes da ativação, preservar a versão anterior, hash, manifesto, configuração compatível e metadados de dependência.

Monitorar erros, latência, recursos, integrações, contratos e qualidade dos resultados. Em caso de degradação:

1. Registrar incidente e bloquear evoluções relacionadas.
2. Avaliar a versão ativa.
3. Executar rollback conforme política.
4. Restaurar a referência estável por CAS.
5. Verificar integridade.
6. Registrar evidências.

Rollback não apaga versão defeituosa ou suas evidências.

## 6. Máquina de estados

Estados:

| Estado | Descrição |
|---|---|
| PROPOSED | Proposta criada |
| VALIDATING | Validação em execução |
| VALIDATED | Candidato validado |
| AWAITING_APPROVAL | Aguardando decisão humana |
| APPROVED | Aprovação registrada |
| ACTIVATING | Ativação em andamento |
| ACTIVE | Nova versão ativa |
| ROLLING_BACK | Recuperação em andamento |
| ROLLED_BACK | Versão anterior restaurada |
| CHANGES_REQUESTED | Revisão solicitada; requer nova proposta e novo artefato |\n| REJECTED | Proposta ou candidato rejeitado |
| FAILED | Processo encerrado por falha |

Uma solicitação de alterações encerra a proposta atual; a revisão deve criar uma nova proposta e um novo hash. Transições proibidas incluem PROPOSED para APPROVED, VALIDATING para ACTIVATING, REJECTED para APPROVED e qualquer caminho para ACTIVE que não passe pela validação, aprovação e controlador de ativação. Cada transição gera evento auditável.

## 7. Requisitos funcionais

| ID | Requisito | Prioridade |
|---|---|---|
| FR-001 | Detectar falhas e oportunidades | Must |
| FR-002 | Criar propostas estruturadas | Must |
| FR-003 | Identificar componentes e versões | Must |
| FR-004 | Sintetizar candidatos | Must |
| FR-005 | Executar candidatos em sandbox | Must |
| FR-006 | Executar testes unitários e de integração | Must |
| FR-007 | Executar testes adversariais | Must |
| FR-008 | Produzir relatório de validação ligado ao hash | Must |
| FR-009 | Exigir aprovação humana autenticada | Must |
| FR-010 | Vincular aprovação ao artefato e relatório | Must |
| FR-011 | Ativar por CAS | Must |
| FR-012 | Preservar versões anteriores | Must |
| FR-013 | Monitorar versões recém-ativadas | Must |
| FR-014 | Recuperar versões estáveis por CAS | Must |
| FR-015 | Auditar todas as transições | Must |
| FR-016 | Comparar versões | Should |
| FR-017 | Aplicar políticas por criticidade | Should |
| FR-018 | Relatar evolução contínua | Should |
| FR-019 | Evoluir ferramentas e comportamentos | Should |
| FR-020 | Integrar publicação a CI/CD e GitHub | Could |

## 8. Requisitos não funcionais

**Segurança:** fail-closed; nenhum código LLM executado diretamente em produção; separação entre geração, autorização e execução; privilégio mínimo; artefatos imutáveis e verificáveis; aprovação autenticada; proteção contra replay e concorrência; isolamento.

**Confiabilidade:** ativação atômica; recuperação de versões anteriores; registros íntegros; tratamento de falhas parciais; idempotência onde aplicável.

**Observabilidade:** correlacionar ProposalID, ExecutionID, ActorID, TargetID, VersionID, ArtifactHash, ValidationID e ApprovalID.

**Desempenho:** construção e validação não devem bloquear agentes ativos; validação ocorre antes da ativação.

## 9. Arquitetura lógica

1. Evolution Detector.
2. Evolution Planner.
3. Magician / Code Synthesizer.
4. Artifact Manager.
5. Sandbox Orchestrator.
6. Validation Engine.
7. Shadow Evaluator.
8. Sage Evaluator.
9. Human Approval Gateway.
10. Evolution Controller.
11. Atomic Registry.
12. Runtime Health Monitor.
13. Recovery Controller.
14. Evolution Audit Log.

O Evolution Controller é a autoridade de transição do processo.

## 10. Fluxo arquitetural

~~~text
FAILURE / NEW CAPABILITY
          |
    EVOLUTION DETECTOR
          |
     EVOLUTION PLANNER
          |
      PROPOSED CHANGE
          |
    MAGICIAN / SYNTHESIS
          |
     IMMUTABLE ARTIFACT
          |
    ISOLATED SANDBOX
          |
    VALIDATION + SHADOW
          |
      SAGE EVALUATION
          |
      VALIDATION REPORT
          |
       HUMAN APPROVAL
          |
      SUPEREGO POLICY
          |
    EVOLUTION CONTROLLER
          |
         CAS CHECK
          |
      ATOMIC HOT-SWAP
          |
      HEALTH MONITOR
        /       \
    HEALTHY   DEGRADED
       |          |
     ACTIVE    ROLLBACK
                  |
             LAST KNOWN GOOD
~~~

## 11. Métricas

- Proposal Acceptance Rate.
- Validation Pass Rate.
- Regression Rate.
- Activation Success Rate.
- Rollback Rate.
- Mean Time to Recovery.
- Evolution Lead Time.
- Security Rejection Rate.
- Version Integrity.
- Policy Violation Count.

O objetivo não é maximizar a quantidade de evoluções, mas a melhoria comprovada sem aumentar o risco operacional.

## 12. Critérios de aceite

- [ ] Criar proposta a partir de falha documentada.
- [ ] Produzir artefato sem acesso à produção.
- [ ] Validar em ambiente isolado.
- [ ] Executar testes funcionais, integração e adversariais.
- [ ] Produzir relatório ligado ao hash exato.
- [ ] Impedir aprovação de candidatos reprovados.
- [ ] Vincular aprovação autenticada a proposta, hash e relatório.
- [ ] Invalidar autorização quando o artefato mudar.
- [ ] Impedir CAS com geração desatualizada.
- [ ] Fazer hot-swap preservando versão anterior.
- [ ] Simular falha e executar rollback verificável.
- [ ] Auditar todas as transições.
- [ ] Não executar código gerado diretamente em produção.

## 13. Escopo do MVP

**Incluído:** Evolution Proposal, versionamento imutável, sandbox, testes automatizados, Shadow Evaluation, Validation Report, Human Approval Gateway, hash verification, CAS Registry, hot-swap de componentes carregados, versões anteriores, rollback, auditoria e CI.

**Fora do MVP:** autoaprovação, execução direta de código gerado, modificação autônoma de políticas, deploy irrestrito, credenciais externas irrestritas, publicação sem validação e evolução recursiva sem limites.

## 14. Roadmap

| Fase | Entrega |
|---|---|
| P0 | Propostas e máquina de estados |
| P1 | Artifact Manager e versionamento imutável |
| P2 | Sandbox e Validation Engine |
| P3 | Shadow e Sage Evaluation |
| P4 | Human Approval Gateway |
| P5 | Atomic Registry e CAS Hot-Swap |
| P6 | Health Monitor e Rollback |
| P7 | Auditoria e observabilidade |
| P8 | CI/CD e GitHub |
| P9 | Evolução adaptativa de ferramentas e comportamentos |

## 15. Diretriz arquitetural

O Evolutionary Engine segue o princípio de **Governed Self-Evolution**.

- Autonomia para identificar oportunidades.
- Autonomia para preparar propostas.
- Validação automatizada e independente.
- Autorização governada.
- Ativação atômica.
- Recuperação reversível.
- Auditoria de ponta a ponta.

**Resultado esperado:** um substrate multiagente capaz de evoluir suas capacidades sem execução irrestrita de código, preservando segurança, disponibilidade e integridade operacional.

**Definição de sucesso:** o sistema aprende com suas falhas, transforma evidências em melhorias verificáveis e incorpora evoluções aprovadas sem comprometer a estabilidade das capacidades existentes.


## Implementation addendum — sandbox and recovery boundaries

The reference implementation uses a digest-pinned container image and a static command matrix. The runner disables networking, uses a read-only root filesystem and artifact mount, drops Linux capabilities, enforces no-new-privileges and numeric non-root execution, and applies CPU, memory, PID, time, output and artifact-size bounds. The validation image and container engine remain trusted components.

Local durability is provided by SQLiteArtifactStore and SQLiteNonceStore. Both are intended for a local durable filesystem; multi-host deployments require object storage and a shared transactional nonce service.

The prepared artifact loader maps a verified digest to a handler that has already been prepared by trusted build code. It does not import or execute LLM-generated source. The runtime health monitor consumes metrics supplied by the host application and can trigger CAS rollback according to configured thresholds; it does not collect telemetry or distribute a rollback across hosts.
