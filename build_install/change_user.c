#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>


void help(char *pname)
{
    printf("usage: %s <username> <binary_path>\n", pname);
    printf("For example:\n");
    printf("\t%s ftpvrpv8 /bin/sh\n", pname);
}

int main(int argc, char *argv[])
{
    if(argc < 3){
        help(argv[0]);
        exit(1);
    }
    
    struct passwd *user;
    struct group *gr;
    int ngroups;

    user = getpwnam(argv[1]);
    if( user == NULL)
    {
        perror("get user failed");
	exit(2);
    }
    gr = malloc(100 * sizeof(gid_t));
    getgrouplist(argv[1], user->pw_gid, gr, &ngroups); 
    setgid(user->pw_gid);
    setgroups(ngroups, gr);
    if(-1 == setuid(user->pw_uid))
    {
	printf("change user failed\n");
    }else{
    	system(argv[2]);
    }
    return 0;

}
