"""
main.py — Ponto de entrada e menu principal do SecuraPy SIEM.

Importa e orquestra todos os módulos do sistema, conforme a estrutura
definida na Seção 4 do enunciado (Integração dos Módulos).
"""

import os
import sys
from datetime import datetime

# Garante que o terminal exibe corretamente caracteres UTF-8 (ex: caracteres do menu)
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

from coletor import carregar_todos_os_logs
from regras import carregar_regras, aplicar_regras
from detector import (
    detectar_brute_force,
    detectar_port_scan,
    verificar_blacklist,
    gerar_resumo_ameacas,
)
from enriquecimento import enriquecer_alertas, exibir_enriquecimento
from relatorios import (
    exibir_menu,
    resumo_geral,
    filtrar_eventos,
    buscar_ip,
    top_ips,
    exportar_relatorio_json,
)

# Configurações
PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


def _serializar_resumo(resumo):
    """
    Converte recursivamente sets em listas para que o resumo de ameacas
    possa ser serializado como JSON (sets nao sao suportados pelo json.dump).
    """
    if isinstance(resumo, list):
        return [_serializar_resumo(item) for item in resumo]
    if isinstance(resumo, dict):
        return {chave: _serializar_resumo(valor) for chave, valor in resumo.items()}
    if isinstance(resumo, set):
        return sorted(list(resumo))
    return resumo


def main():

    eventos = []
    alertas = []
    alertas_enriquecidos = []
    resumo_ameacas = []
    cache_enriquecimento = {}
    logs_carregados = False

    while True:
        opcao = exibir_menu()

        if opcao == 1:
            # Carregar e processar logs
            eventos = carregar_todos_os_logs(PASTA_LOGS)

            if not eventos:
                print("Nenhum evento foi carregado. Verifique a pasta de logs.")
                continue

            regras = carregar_regras(ARQUIVO_REGRAS)
            alertas = aplicar_regras(eventos, regras)

            brute_force = detectar_brute_force(eventos)
            port_scan = detectar_port_scan(eventos)
            resultado_blacklist = verificar_blacklist(eventos, BLACKLIST)
            ips_blacklist = resultado_blacklist[0]
            resumo_ameacas = gerar_resumo_ameacas(brute_force, port_scan, resultado_blacklist)

            logs_carregados = True

            contadores_fonte = {"auth": 0, "firewall": 0, "web": 0}
            for evento in eventos:
                fonte = evento.get("fonte")
                if fonte in contadores_fonte:
                    contadores_fonte[fonte] += 1

            print(
                f"{contadores_fonte['auth']} eventos de auth, "
                f"{contadores_fonte['firewall']} de firewall, "
                f"{contadores_fonte['web']} de web. "
                f"Total: {len(eventos)} eventos"
            )
            print(f"{len(alertas)} alertas gerados pelo motor de regras.")
            print(f"{len(resumo_ameacas)} IPs suspeitos identificados pelo detector.")

        elif opcao == 2:
            # Resumo geral
            if not logs_carregados:
                print("Carregue os logs primeiro (opção 1)")
                continue
            resumo_geral(eventos, alertas)

        elif opcao == 3:
            # Filtrar eventos
            if not logs_carregados:
                print("Carregue os logs primeiro (opção 1)")
                continue

            fonte = input("Fonte (auth/firewall/web ou Enter para ignorar): ").strip() or None
            tipo = input("Tipo (FAIL/BLOCK/... ou Enter para ignorar): ").strip() or None
            ip = input("IP (ou Enter para ignorar): ").strip() or None

            eventos_filtrados = filtrar_eventos(eventos, fonte=fonte, tipo=tipo, ip=ip)

            print(f"{len(eventos_filtrados)} eventos encontrados.")
            for evento in eventos_filtrados:
                print(evento.get("linha_original", evento))

        elif opcao == 4:
            # Buscar IP
            if not logs_carregados:
                print("Carregue os logs primeiro (opção 1)")
                continue

            ip = input("Digite o IP a ser pesquisado: ").strip()
            buscar_ip(ip, eventos, alertas, cache_enriquecimento)

        elif opcao == 5:
            # Top 10 IPs suspeitos
            if not logs_carregados:
                print("Carregue os logs primeiro (opção 1)")
                continue

            ranking = top_ips(eventos, n=10)
            for posicao, item in enumerate(ranking, start=1):
                print(f"{posicao}. {item}")

        elif opcao == 6:
            # Ver alertas por severidade
            if not logs_carregados:
                print("Carregue os logs primeiro (opção 1)")
                continue

            alertas_por_severidade = {}
            for alerta in alertas:
                severidade = alerta.get("severidade", "INFO")
                alertas_por_severidade.setdefault(severidade, []).append(alerta)

            for severidade in ("CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"):
                lista = alertas_por_severidade.get(severidade, [])
                print(f"\n[{severidade}] — {len(lista)} alerta(s)")
                for alerta in lista:
                    print(
                        f"  {alerta.get('timestamp')} — {alerta.get('regra')} "
                        f"— {alerta.get('ip')} — {alerta.get('descricao')}"
                    )

        elif opcao == 7:
            # Enriquecer IPs suspeitos
            if not logs_carregados:
                print("Carregue os logs primeiro (opção 1)")
                continue

            if not alertas:
                print("Nenhum alerta para enriquecer.")
                continue

            alertas_enriquecidos = enriquecer_alertas(alertas, cache_enriquecimento)

            for alerta in alertas_enriquecidos:
                print(f"\nAlerta: {alerta.get('regra')} — IP: {alerta.get('ip')}")
                exibir_enriquecimento(alerta.get("enriquecimento", {}))

        elif opcao == 8:
            # Exportar relatório JSON
            if not logs_carregados:
                print("Carregue os logs primeiro (opção 1)")
                continue

            dados_relatorio = {
                "gerado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_eventos": len(eventos),
                "total_alertas": len(alertas),
                "resumo_ameacas": _serializar_resumo(resumo_ameacas),
                "alertas": alertas_enriquecidos if alertas_enriquecidos else alertas,
            }

            os.makedirs("saida", exist_ok=True)
            nome_arquivo = datetime.now().strftime("relatorio_%Y%m%d_%H%M%S.json")
            caminho = os.path.join("saida", nome_arquivo)

            exportar_relatorio_json(dados_relatorio, caminho)
            print(f"Relatório exportado em: {caminho}")

        elif opcao == 9:
            # Iniciar servidor de alertas
            from servidor_alertas import iniciar_servidor

            print("Iniciando servidor de alertas SecuraPy...")
            iniciar_servidor()

        elif opcao == 0:
            print("Encerrando SecuraPy. Até logo!")
            break


if __name__ == "__main__":
    main()