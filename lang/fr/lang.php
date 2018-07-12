<?php
# User menu text
$lang['btn_twofactor_profile'] = 'Paramètres de double authentification';

# Two Factor profile header and settings
$lang['settings'] = "Two Factor Settings";
$lang['twofactor_optin'] = "Utiliser la double authentification";
$lang['twofactor_notify'] = "Send notification upon sucessful login to default device";
$lang['defaultmodule'] = "Méthode par défaut pour recevoir un code";
$lang['useallotp'] = "*Tout utiliser*";
$lang['verify_password'] = "Confirmez votre mot de passe";
$lang['btn_quit'] = "Quitter";
$lang['btn_return'] = "Retourner sur le wiki";

# Messages displayed by menu
$lang['updated'] = "Configuration de double authentification mise à jour.";
$lang['mandatory'] = "Ce wiki requiert l'utilisation d'une double authentification. Vous devez configurer au moins une méthode de double authentification pour continuer.";
$lang['optout_notice'] = "This wiki has the ability to use two factor authentication.  If you do not want to use this option, please uncheck the first box below, supply your password at the bottom, and save your settings.";

# Text used at login
$lang['twofactor_login'] = "Jeton d'authentification 2FA <br />(laissez vide si inutilisé)<br />";
$lang['mustusetoken'] = "Ce wiki requiert l'utilisation d'un fournisseur de jeton d'authentification comme Google Authentificator pour s'identifier.";

# Text used at OTP login screen
$lang['twofactor_otplogin'] = "Code de vérification";
$lang['twofactor_useallmods'] = "Renvoyer un code OTP en utilisant toutes les méthodes configurées";
$lang['twofactor_invalidotp'] = "Le code fourni est incorrect ou expiré. Merci de réessayer. Si besoin, cliquez sur le lien pour renvoyer un code.";
$lang['btn_login'] = "Complétez l'identification";
$lang['btn_resend'] = "Renvoyer un code";

# LogLog text
# 'logged in, %s'
$lang['requires_otp'] = "requires OTP code";
# 'logged in, %s'
$lang['2fa_mandatory'] = "redirected to 2FA for mandatory setup";
# 'logged in %s'
$lang['token_ok'] = "using correct token";
# 'failed %s'
$lang['no_tokens'] = "token login, no tokens configured";
# 'failed %s'
$lang['token_mismatch'] = "token login, no token match";
# 'logged off, %s'
$lang['quit_otp'] = "quit OTP screen";
# 'logged in %s'
$lang['otp_ok'] = "using OTP screen";
# 'failed OTP login, %s'
$lang['otp_mismatch'] = "bad code";

# Administrative text
$lang['menu'] = 'Administration de double authentification';
$lang['noauth']      = "Impossible d'administrer la double authentification : module d'authentification utilisateur non disponible.";
$lang['nosupport']   = "Impossible d'administrer la double authentification : gestion des utilisateurs non suportée par le module d'authentification.";
$lang['badauth']     = "mécanisme d'authentification invalide";     // ne devrait jamais s'afficher !
$lang['user_id']     = 'Utilisateur';
$lang['user_pass']   = 'Mot de passe';
$lang['user_name']   = 'Nom réel';
$lang['user_mail']   = 'E-mail';
$lang['reset_selected'] = 'Remettre à zéro la sélection';
$lang['search']      = 'Recherche';
$lang['search_prompt'] = 'Lancer la recherche';
$lang['clear']       = 'Remettre à zéro le filtre de recherche';
$lang['filter']      = 'Filtre';
$lang['start']  = 'début';
$lang['prev']   = 'précédent';
$lang['next']   = 'suivant';
$lang['last']   = 'dernier';
$lang['summary']     = 'Affichage utilisateurs %1$d-%2$d sur %3$d trouvés. %4$d utilisateurs au total.';
$lang['nonefound']   = 'Aucun utilisateur trouvé. %d utilisateurs au total.';
$lang['reset_ok']   = '%d utilisateurs remis à zéro';
$lang['reset_not_self']   = "Vous ne pouvez pas vous remettre à zéro.";
$lang['no_purpose']   = "L'extension TwoFactor dépend de l'extension Attribute. Sans l'extension Attribute, TwoFactor ne peut pas stocker de données et ne fonctionnera pas.";
