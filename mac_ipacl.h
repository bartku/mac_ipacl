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

#include <sys/types.h>
#include <sys/queue.h>

#define MAC_RULE_STRING_LEN	1024
#define RULE_GID	1
#define RULE_UID	2
#define GID_STRING	"gid"
#define UID_STRING	"uid"

/* Macros for goto elements. */
#define	CHECK_ELEMENT(x)	do {	\
		if ((x) == NULL) {			\
			error = EINVAL;			\
			goto out;				\
		}							\
} while (0)

#define GOTO_EINVAL(x, y)	do {	\
		(x) = EINVAL;				\
		goto y;						\
} while (0)

static char rules_string[MAC_RULE_STRING_LEN];
static char addr_exempt_string[MAC_RULE_STRING_LEN];

TAILQ_HEAD(tailhead_addr, addr_exempt) addr_head = TAILQ_HEAD_INITIALIZER(addr_head);
struct tailhead_addr *heada;

struct addr_exempt {
		struct in_addr				addr;
		TAILQ_ENTRY(addr_exempt)	addr_exempts;
};

TAILQ_HEAD(tailhead, ipacl_rule) rule_head = TAILQ_HEAD_INITIALIZER(rule_head);
struct tailhead *headi;

struct ipacl_rule {
		unsigned int			idtype;
		unsigned int			id;
		struct in_addr 			addr;
		TAILQ_ENTRY(ipacl_rule) ipacl_rules;
};

static void	destroy_rules(struct tailhead *);
static void	ipacl_init(struct mac_policy_conf *);
static void	ipacl_destroy(struct mac_policy_conf *);
static int	parse_rule_element(char *, struct ipacl_rule **);
static int	parse_rules(char *, struct tailhead *);
static int	parse_addr_exempt(char *, struct tailhead_addr *);
static int	sysctl_addr_exempt(struct sysctl_oid *, void *, int, struct sysctl_req *);
static int	sysctl_rules(struct sysctl_oid *, void *, int, struct sysctl_req *);
static int	rules_check(struct ucred *, struct sockaddr *);
static int	ipacl_socket_check_bind(struct ucred *, struct socket *, struct label *, struct sockaddr *);

