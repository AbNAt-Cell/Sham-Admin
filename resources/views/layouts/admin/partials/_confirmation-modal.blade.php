<!-- confirmation moddal -->
<div class="modal fade" id="globalConfirmationModal" tabindex="-1" role="dialog" aria-labelledby="exampleModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close fz-20" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body">
                <div class="text-center">
                    <div class="my-4">
                        <img id="globalConfirmationModalImage" src="{{ asset('public/assets/admin/img/halal-tags.png') }}" alt="Checked Icon">
                    </div>
                    <div class="my-4">
                        <h3 id="globalConfirmationModalTitle"></h3>
                        <p id="globalConfirmationModelMessage"></p>
                    </div>
                    <div class="my-4 d-flex justify-content-center gap-2">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal">{{ translate('Cancel') }}</button>
                        <button type="button" class="btn btn-primary" id="globalConfirmationModalConfirmButton">{{ translate('Yes') }}</button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
