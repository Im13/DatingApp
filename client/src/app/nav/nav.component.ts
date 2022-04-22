import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { ToastrService } from 'ngx-toastr';
import { AccountService } from '../_services/account.service';

@Component({
  selector: 'app-nav',
  templateUrl: './nav.component.html',
  styleUrls: ['./nav.component.css']
})
export class NavComponent implements OnInit {
  model: any = {};
  loggedIn: boolean = false;

  constructor(public accountService: AccountService, private router: Router, private toastr: ToastrService) { }

  ngOnInit(): void {
  }

  login(){
    this.accountService.login(this.model).subscribe({
      next: (response) => {
        this.router.navigateByUrl('/members');
        this.loggedIn = true;
      }
    });
  }

  logout() {
    this.accountService.logout();
    this.loggedIn = false;
    this.router.navigateByUrl('/');
  }
}
