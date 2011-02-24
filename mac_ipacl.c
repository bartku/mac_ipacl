/*-
 * Copyright (c) 2010-2011 Bartosz Marcin Kojak <bartek@6bone.be>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/ctype.h>
#include <sys/domain.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/sbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>

#include <netinet/in.h>

#include <security/mac/mac_policy.h>

#include "mac_ipacl.h"

SYSCTL_DECL(_security_mac);
SYSCTL_NODE(_security_mac, OID_AUTO, ipacl, CTLFLAG_RW, 
		0, "mac_ipacl policy controls");

static int	ipacl_enabled = 1;
SYSCTL_INT(_security_mac_ipacl, OID_AUTO, enabled, CTLFLAG_RW, 
		&ipacl_enabled, 0, "Enforce ipacl policy");
TUNABLE_INT("security.mac.ipacl.enabled", &ipacl_enabled);

/* Exception: allow the root user to bind to any address. */
static int	ipacl_suser_exempt = 1;
SYSCTL_INT(_security_mac_ipacl, OID_AUTO, suser_exempt, CTLFLAG_RW, 
		&ipacl_suser_exempt, 0, "Allow the root user to bind to any address");
TUNABLE_INT("security.mac.ipacl.suser_exempt", &ipacl_suser_exempt);

static int	ipacl_debug = 0;
SYSCTL_INT(_security_mac_ipacl, OID_AUTO, debug, CTLFLAG_RW, &ipacl_debug,
				0, "Debug output");
TUNABLE_INT("security.mac.ipacl.debug", &ipacl_debug);

SYSCTL_PROC(_security_mac_ipacl, OID_AUTO, addr_exempt, CTLTYPE_STRING|CTLFLAG_RW, 0, 0, sysctl_addr_exempt, "A", "IP address(es) available for all users");
SYSCTL_PROC(_security_mac_ipacl, OID_AUTO, rules, CTLTYPE_STRING|CTLFLAG_RW, 0, 0, sysctl_rules, "A", "Rules");

MALLOC_DEFINE(M_IPACL, "mac_ipacl", "Rules in mac_ipacl");
MALLOC_DEFINE(M_ADDR_EXEMPT, "mac_addr_exempt", "Addr exempt");

#if 0
struct ipacl_rule ip_rule = {
		.idtype = RULE_UID,
		.id = 1001,
};
#endif

static struct	mtx ipacl_mtx;

/* Destroying ipacl_rule queue after being used. */

static void
destroy_rules(struct tailhead *head)
{
		struct ipacl_rule *n1, *n2;

		mtx_lock(&ipacl_mtx);

		n1 = TAILQ_FIRST(head);
		while (n1 != NULL) {
				n2 = TAILQ_NEXT(n1, ipacl_rules);
				free(n1, M_IPACL);
				n1 = n2;
		}

		mtx_unlock(&ipacl_mtx);
}

static void
destroy_addr_exempt(struct tailhead_addr *head)
{
		struct addr_exempt *n1, *n2;

		mtx_lock(&ipacl_mtx);

		n1 = TAILQ_FIRST(head);
		while (n1 != NULL) {
				n2 = TAILQ_NEXT(n1, addr_exempts);
				free(n1, M_ADDR_EXEMPT);
				n1 = n2;
		}

		mtx_unlock(&ipacl_mtx);
}

/* Initializating mutex and queues.  Called while loading module.  */

static void
ipacl_init(struct mac_policy_conf *conf)
{
		mtx_init(&ipacl_mtx, "ipacl_mtx", NULL, MTX_DEF);
		TAILQ_INIT(&rule_head);
		TAILQ_INIT(&addr_head);
}

/* Destroying mutex and queues, no longer needed.  Called while unloading 
 * module. */

static void
ipacl_destroy(struct mac_policy_conf *conf)
{
		destroy_addr_exempt(&addr_head);
		destroy_rules(&rule_head);
		mtx_destroy(&ipacl_mtx);
}

/* Parses single rule element and puts values into proper fields in 
 * struct ipacl_rule. */

static int
parse_rule_element(char *element, struct ipacl_rule **ip_rule)
{
		char *idtype, *id, *ip, *endptr;
		struct ipacl_rule *new_rule;
		char *delim = ":";
		int error = 0;

		new_rule = malloc(sizeof(struct ipacl_rule), M_IPACL, M_WAITOK|M_ZERO);

		idtype = strsep(&element, delim);
		CHECK_ELEMENT(idtype);

		id = strsep(&element, delim);
		CHECK_ELEMENT(id);

		ip = element;
		CHECK_ELEMENT(ip);

		new_rule->id = strtol(id, &endptr, 10);	/* Instead of missing atoi. */
		if (*endptr != '\0')
				GOTO_EINVAL(error, out);

		if (strncmp(idtype, GID_STRING, sizeof(GID_STRING)) == 0)
				new_rule->idtype = RULE_GID;
		else if (strncmp(idtype, UID_STRING, sizeof(UID_STRING)) == 0)
				new_rule->idtype = RULE_UID;
		else
				GOTO_EINVAL(error, out);

		if (inet_aton(ip, &new_rule->addr) != 1)
				GOTO_EINVAL(error, out);

out:
		if (error != 0) {
				free(new_rule, M_IPACL);
				*ip_rule = NULL;
		}
		else
				*ip_rule = new_rule;
		return (error);
}

/* Parses whole mac_ipacl rule by comma. */

static int
parse_rules(char *string, struct tailhead *head)
{
		struct ipacl_rule *new;
		char *element;
		int error = 0;

		while ((element = strsep(&string, ",")) != NULL) {
				if (strlen(element) == 0)
						continue;
				error = parse_rule_element(element, &new);

				if (error)
						goto out;
				TAILQ_INSERT_TAIL(head, new, ipacl_rules);
		}

out:
		if (error != 0)
				destroy_rules(head);
		return (error);
}

static int
parse_addr_exempt(char *string, struct tailhead_addr *head)
{
		struct addr_exempt *new;
		char *element;
		int error = 0;

		while ((element = strsep(&string, ",")) != NULL) {
				if (strlen(element) == 0)
						continue;
				new = malloc(sizeof(struct addr_exempt), M_ADDR_EXEMPT, M_WAITOK|M_ZERO);

				if (inet_aton(element, &new->addr) != 1)
						GOTO_EINVAL(error, out);
				TAILQ_INSERT_TAIL(head, new, addr_exempts);
		}

out:
		if (error != 0) {
				free(new, M_ADDR_EXEMPT);
		}

		return (error);
}

/*
 * Taking string from sysctl.mac.ipacl.addr_exempt and passing it forward.
 * */

static int
sysctl_addr_exempt(SYSCTL_HANDLER_ARGS)
{
		struct tailhead_addr head1, head2;
		char *ip;
		char *string, *sbuf, *snew;
		int error;

		error = 0;
		string = NULL;
		sbuf = NULL;
		snew = NULL;
		ip = NULL;

		if (req->newptr != NULL) {
				snew = malloc(MAC_RULE_STRING_LEN, M_ADDR_EXEMPT, M_WAITOK | M_ZERO);
				mtx_lock(&ipacl_mtx);
				strlcpy(snew, addr_exempt_string, MAC_RULE_STRING_LEN);
				mtx_unlock(&ipacl_mtx);
				string = snew;
		}
		else
				string = addr_exempt_string;

		error = sysctl_handle_string(oidp, string, MAC_RULE_STRING_LEN, req);

		if (error)
				goto out;

		if (req->newptr != NULL) {
				sbuf = strdup(string, M_ADDR_EXEMPT);
				TAILQ_INIT(&head1);
				error = parse_addr_exempt(sbuf, &head1);
				free(sbuf, M_ADDR_EXEMPT);

				if (error)
						goto out;

				TAILQ_INIT(&head2);
				mtx_lock(&ipacl_mtx);
				TAILQ_CONCAT(&head2, &addr_head, addr_exempts);
				TAILQ_CONCAT(&addr_head, &head1, addr_exempts);
				strlcpy(addr_exempt_string, string, MAC_RULE_STRING_LEN);

				mtx_unlock(&ipacl_mtx);
				destroy_addr_exempt(&head2);
		}

out:
		if (snew != NULL)
				free(snew, M_ADDR_EXEMPT);
		return (error);
}
/* 
 * Taking string from sysctl.mac.ipacl.rules and passing it to parse_rules().  
 * Need to be declared as SYSCTL_PROC to handle sysctl rules.  Function is 
 * executed everytime sysctl.mac.ipacl.rules is changed. */

static int
sysctl_rules(SYSCTL_HANDLER_ARGS)
{
		struct tailhead head1, head2;
		char *string, *sbuf, *snew;
		int error;

		snew = NULL;

		if (req->newptr != NULL) {
				snew = malloc(MAC_RULE_STRING_LEN, M_IPACL, M_WAITOK | M_ZERO);
				mtx_lock(&ipacl_mtx);
				strlcpy(snew, rules_string, MAC_RULE_STRING_LEN);
				mtx_unlock(&ipacl_mtx);
				string = snew;
		}
		else
				string = rules_string;

		error = sysctl_handle_string(oidp, string, MAC_RULE_STRING_LEN, req);	/* Takes SYSCTL_HANDLER_ARGS as argument */
		
		if (error)
				goto out;

		if (req->newptr != NULL) {
				sbuf = strdup(string, M_IPACL);
				TAILQ_INIT(&head1);
				error = parse_rules(sbuf, &head1);
				free(sbuf, M_IPACL);
				if (error)
						goto out;

				TAILQ_INIT(&head2);
				mtx_lock(&ipacl_mtx);
				TAILQ_CONCAT(&head2, &rule_head, ipacl_rules);
				TAILQ_CONCAT(&rule_head, &head1, ipacl_rules);
				strlcpy(rules_string, string, MAC_RULE_STRING_LEN);
				mtx_unlock(&ipacl_mtx);
				destroy_rules(&head2);
		}


out:
		if (snew != NULL)
				free(snew, M_IPACL);
		return (error);
}

/* Checking if given user fits to rules.  Returns 0 on success.*/

static int
rules_check(struct ucred *ucred, struct sockaddr *sa)
{
		struct ipacl_rule *rule;
		struct addr_exempt *exempt;
		int error = EPERM;

		mtx_lock(&ipacl_mtx);

		TAILQ_FOREACH(rule, &rule_head, ipacl_rules) {
				if (memcmp(&rule->addr, &(((struct sockaddr_in*)sa)->sin_addr), sizeof(struct in_addr)) == 0) {
					switch (rule->idtype) {
					case RULE_UID:
							if (ucred->cr_uid == rule->id) {
									error = 0;
									continue;
							}
							break;
					case RULE_GID:
							if (ucred->cr_gid == rule->id || groupmember(rule->id, ucred)) {
									error = 0;
									continue;
							}
							break;
					default:
							break;
					}
				}
		}


		TAILQ_FOREACH(exempt, &addr_head, addr_exempts) {
				if (memcmp(&exempt->addr, &(((struct sockaddr_in*)sa)->sin_addr), sizeof(struct in_addr)) == 0) {
						error = 0;
						break;
				}
		}
		
		/* If suser_exempt is enabled and rule for root doesn't exist in 
		 * rules, check of user is root. */
		if (error != 0 && ipacl_suser_exempt != 0)
				if (ucred->cr_uid == 0)
						error = 0;

		mtx_unlock(&ipacl_mtx);

		return (error);
}


/* Executed with every socket(2) call by specified user. Return 0 on success. */

static int
ipacl_socket_check_bind(struct ucred *ucred, struct socket *so, struct label *sl, struct sockaddr *sa)
{
		/* Work only when policy is enabled. */
		if (ipacl_enabled == 0)
			return 0;

		/* Only interested in IPv4 sockets. */
		if (so->so_proto->pr_domain->dom_family != PF_INET)
			return 0;

		/* Do not work on raw sockets. */
		if (so->so_type != SOCK_DGRAM && so->so_type != SOCK_STREAM)
			return 0;

		/* Addressess other than IP. */
		if (sa->sa_family != AF_INET)
			return EINVAL;

		return(rules_check(ucred, sa));
}

static struct
mac_policy_ops ipacl_ops = {
		.mpo_init = ipacl_init,
		.mpo_destroy = ipacl_destroy,
		.mpo_socket_check_bind = ipacl_socket_check_bind,
};

MAC_POLICY_SET(&ipacl_ops, mac_ipacl, "Not TrustedBSD MAC/ipacl", 
		MPC_LOADTIME_FLAG_UNLOADOK, NULL);
MODULE_VERSION(mac_ipacl, 1);

